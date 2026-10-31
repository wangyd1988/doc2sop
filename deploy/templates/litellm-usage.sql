\encoding UTF8
\set ON_ERROR_STOP on
-- LiteLLM 用量的只读接口：在 LiteLLM 自己的 Postgres 里建两个角色、一个 schema 和三个函数，
-- 给 deploy/templates/litellm-usage.yaml 里的三个工具用。说明见 docs/正式部署.md「例：LiteLLM 网关的用量」。
-- （开头两行要在任何非 ASCII 字符之前：本文件是 UTF-8，客户端编码是别的（比如 GBK）时不先切换，psql 会按错的编码读后面的中文。）
--
-- 用法：在数据库所在的机器上，以库的超级用户执行。dbname 必须和 -d 连的库一致（防止建错库，比如升级前的旧库）：
--   docker exec -i <Postgres 容器> psql -X -v ON_ERROR_STOP=1 -v dbname=<库名> -U <超级用户> -d <库名> < litellm-usage.sql
-- 在用的库名看 LiteLLM 容器的 DATABASE_URL，不一定是 POSTGRES_DB。
--
-- 可以重复执行：角色已有就跳过，schema 已有就跳过，函数 CREATE OR REPLACE（改了函数返回的列要先 DROP FUNCTION）。
-- LiteLLM 升级换了库（新建一个库再切过去），就在新库里再执行一遍，并把工具服务连接的 database 改成新库。
--
-- 密码不在这里设：在工具服务那台机器上生成密码、算出 SCRAM-SHA-256 校验值，只把校验值经 stdin 交给 psql：
--   ALTER ROLE doc2sop_ro PASSWORD 'SCRAM-SHA-256$4096:<salt>$<StoredKey>:<ServerKey>';
--
-- 为什么是函数而不是视图：LiteLLM 每次启动都跑 prisma migrate deploy 和 migrate diff。普通视图会在 pg_depend 里记下对
-- 具体列的依赖，以后的迁移删列、改类型、重建表时会被挡住（cannot drop column … because other objects depend on it），
-- 网关就起不来。字符串函数体（$$…$$）只在创建时校验、不记录依赖，迁移看不见它；列变了只是函数调用报错，重新执行本文件即可。
-- 不要改成 BEGIN ATOMIC 写法：那种函数体会记录依赖。对象都放在独立的 schema doc2sop：Prisma 只管 public，看不到这里。
--
-- 安全：函数是 SECURITY DEFINER，属主 doc2sop_definer 不能登录，只有用到的几列的列级 SELECT（列级授权不挡迁移：
-- 删列、改类型、删表时权限跟着消失）；固定 search_path，表名都带 schema，没有动态 SQL，参数只有整数并夹紧范围。
-- doc2sop_ro 只能执行这三个函数；底层表、LiteLLM 自带的视图一律读不到；默认只读事务、5 秒语句超时、最多 3 个连接。
\if :{?dbname}
\else
  DO $$ BEGIN RAISE EXCEPTION 'pass -v dbname=<database> (the same database as -d): nothing was changed'; END $$;
\endif
SELECT set_config('doc2sop.expected_db', :'dbname', false) AS expected_db;
DO $$
BEGIN
  IF current_database() <> current_setting('doc2sop.expected_db') THEN
    RAISE EXCEPTION 'connected to database %, but dbname=%: nothing was changed',
      current_database(), current_setting('doc2sop.expected_db');
  END IF;
END $$;

BEGIN;
-- 等不到锁就整个回滚，不要反复重试
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'doc2sop_definer') THEN
    CREATE ROLE doc2sop_definer NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'doc2sop_ro') THEN
    CREATE ROLE doc2sop_ro LOGIN NOINHERIT CONNECTION LIMIT 3;
  END IF;
END $$;
ALTER ROLE doc2sop_definer NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE doc2sop_ro LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 3;
ALTER ROLE doc2sop_ro SET default_transaction_read_only = on;
ALTER ROLE doc2sop_ro SET statement_timeout = '5s';
ALTER ROLE doc2sop_ro SET idle_in_transaction_session_timeout = '30s';

CREATE SCHEMA IF NOT EXISTS doc2sop AUTHORIZATION doc2sop_definer;
REVOKE ALL ON SCHEMA doc2sop FROM PUBLIC;
GRANT USAGE ON SCHEMA doc2sop TO doc2sop_ro;

GRANT SELECT (date, api_key, model, model_group, api_requests, failed_requests, prompt_tokens,
              completion_tokens, spend, total_response_time_ms, timed_requests)
      ON public."LiteLLM_DailyUserSpend" TO doc2sop_definer;
GRANT SELECT (token, key_alias) ON public."LiteLLM_VerificationToken" TO doc2sop_definer;
GRANT SELECT ("startTime", status, model, model_group, metadata) ON public."LiteLLM_SpendLogs" TO doc2sop_definer;

SET LOCAL ROLE doc2sop_definer;

-- 1) 按模型按天。来源：日汇总表（不受明细保留期影响）；日期是 UTC 日期。
--    返回：day、model（model_group，空则 model）、requests、failed、prompt_tokens、completion_tokens、spend_usd、avg_ms
CREATE OR REPLACE FUNCTION doc2sop.usage_by_model(p_days integer)
RETURNS TABLE (day text, model text, requests bigint, failed bigint, prompt_tokens bigint,
               completion_tokens bigint, spend_usd numeric, avg_ms integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT d.date,
         COALESCE(NULLIF(d.model_group, ''), NULLIF(d.model, ''), '(unknown)'),
         sum(d.api_requests)::bigint,
         sum(d.failed_requests)::bigint,
         sum(d.prompt_tokens)::bigint,
         sum(d.completion_tokens)::bigint,
         round(sum(d.spend)::numeric, 4),
         (sum(d.total_response_time_ms) / NULLIF(sum(d.timed_requests), 0))::integer
    FROM public."LiteLLM_DailyUserSpend" d
   WHERE d.date >= to_char((now() AT TIME ZONE 'UTC')::date
                           - (LEAST(GREATEST(COALESCE(p_days, 7), 1), 90) - 1), 'YYYY-MM-DD')
   GROUP BY 1, 2
   ORDER BY 1 DESC, 3 DESC
$$;

-- 2) 按 key 别名按天。只给别名：不给 key、key 的哈希、key_name 里的 sk-…尾号。
--    返回：day、key_alias、requests、failed、total_tokens、spend_usd
CREATE OR REPLACE FUNCTION doc2sop.usage_by_key(p_days integer)
RETURNS TABLE (day text, key_alias text, requests bigint, failed bigint, total_tokens bigint, spend_usd numeric)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT d.date,
         COALESCE(NULLIF(v.key_alias, ''), '(未命名或已删除的 key)'),
         sum(d.api_requests)::bigint,
         sum(d.failed_requests)::bigint,
         (sum(d.prompt_tokens) + sum(d.completion_tokens))::bigint,
         round(sum(d.spend)::numeric, 4)
    FROM public."LiteLLM_DailyUserSpend" d
    LEFT JOIN public."LiteLLM_VerificationToken" v ON v.token = d.api_key
   WHERE d.date >= to_char((now() AT TIME ZONE 'UTC')::date
                           - (LEAST(GREATEST(COALESCE(p_days, 7), 1), 90) - 1), 'YYYY-MM-DD')
   GROUP BY 1, 2
   ORDER BY 1 DESC, 3 DESC
$$;

-- 3) 最近失败。来源：明细表（最多 168 小时；实际还受 LiteLLM 明细保留期限制）。
--    返回：model、status_code（只放行三位数字）、error_type（只放行类名样式）、failures、first_seen、last_seen
--    （北京时间，固定 UTC+8，不依赖库里的时区数据）。格式不符的一律写成「其他」：报错正文、traceback、请求内容都不出来。
CREATE OR REPLACE FUNCTION doc2sop.recent_failures(p_hours integer)
RETURNS TABLE (model text, status_code text, error_type text, failures bigint, first_seen text, last_seen text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  WITH f AS (
    SELECT COALESCE(NULLIF(s.model_group, ''), NULLIF(s.model, ''), '(unknown)') AS m,
           s.metadata -> 'error_information' ->> 'error_code' AS code,
           s.metadata -> 'error_information' ->> 'error_class' AS cls,
           s."startTime" AS t
      FROM public."LiteLLM_SpendLogs" s
     WHERE s."startTime" >= (now() AT TIME ZONE 'UTC')
                            - make_interval(hours => LEAST(GREATEST(COALESCE(p_hours, 24), 1), 168))
       AND s.status <> 'success'
  )
  SELECT f.m,
         CASE WHEN f.code ~ '^[0-9]{3}$' THEN f.code ELSE '其他' END,
         CASE WHEN f.cls ~ '^[A-Za-z][A-Za-z0-9_.]{0,79}$' THEN f.cls ELSE '其他' END,
         count(*),
         to_char(min(f.t) + interval '8 hours', 'MM-DD HH24:MI'),
         to_char(max(f.t) + interval '8 hours', 'MM-DD HH24:MI')
    FROM f
   GROUP BY 1, 2, 3
   ORDER BY max(f.t) DESC
   LIMIT 100
$$;

RESET ROLE;
REVOKE ALL ON FUNCTION doc2sop.usage_by_model(integer), doc2sop.usage_by_key(integer),
                       doc2sop.recent_failures(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION doc2sop.usage_by_model(integer), doc2sop.usage_by_key(integer),
                          doc2sop.recent_failures(integer) TO doc2sop_ro;
COMMIT;

-- 撤销（在同一个库里执行；先停掉工具服务那边的隧道）：
--   SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'doc2sop_ro';
--   DROP SCHEMA doc2sop CASCADE;
--   DROP OWNED BY doc2sop_ro, doc2sop_definer;      -- 收回列级授权（每个执行过本文件的库都要做）
--   DROP ROLE doc2sop_ro; DROP ROLE doc2sop_definer; -- 角色是整个实例共用的，最后删
