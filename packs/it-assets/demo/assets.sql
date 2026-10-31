-- IT-资产与报修 场景包的演示数据：一份 sqlite 假资产台账和报修工单，人名、型号、编号都是编的。
-- 演示 sidecar 每次启动用它重建数据库（见 deploy/demo/entrypoint.py）。日期都按建库那天往前、往后推：
-- 演示什么时候跑，「在不在保」「快过保了」的结论都一样。
CREATE TABLE assets (
  tag TEXT PRIMARY KEY,          -- 资产编号
  kind TEXT NOT NULL,            -- 笔记本、台式机、显示器、打印机、服务器
  model TEXT NOT NULL,
  owner TEXT NOT NULL,           -- 使用人（公共设备写部门）
  dept TEXT NOT NULL,
  status TEXT NOT NULL,          -- 在用、维修中、闲置、已报废
  purchased TEXT NOT NULL,       -- 购入日期
  warranty_end TEXT NOT NULL     -- 保修截止日期
);

CREATE TABLE tickets (
  id TEXT PRIMARY KEY,           -- 工单号
  tag TEXT NOT NULL REFERENCES assets(tag),
  opened TEXT NOT NULL,
  closed TEXT,                   -- 没关单是 NULL
  priority TEXT NOT NULL,        -- P1、P2、P3
  status TEXT NOT NULL,          -- 处理中、已解决、已转厂商
  summary TEXT NOT NULL
);

INSERT INTO assets VALUES
  ('NB-0042', '笔记本', 'ThinkPad T14 Gen 3', '王敏', '研发部', '在用', date('now', '-1040 days'), date('now', '+55 days')),
  ('NB-0057', '笔记本', 'ThinkPad X1 Carbon Gen 10', '李强', '销售部', '在用', date('now', '-1200 days'), date('now', '-105 days')),
  ('NB-0063', '笔记本', 'MacBook Air M2', '赵雪', '设计部', '维修中', date('now', '-420 days'), date('now', '+675 days')),
  ('NB-0071', '笔记本', 'ThinkPad T14 Gen 4', '陈晨', '研发部', '在用', date('now', '-300 days'), date('now', '+795 days')),
  ('NB-0088', '笔记本', 'ThinkPad E14', '孙磊', '行政部', '闲置', date('now', '-1500 days'), date('now', '-405 days')),
  ('PC-0007', '台式机', 'OptiPlex 7010', '刘洋', '财务部', '在用', date('now', '-1060 days'), date('now', '+35 days')),
  ('PC-0012', '台式机', 'OptiPlex 7090', '周婷', '财务部', '在用', date('now', '-1400 days'), date('now', '-305 days')),
  ('MON-0110', '显示器', 'U2723QE', '王敏', '研发部', '在用', date('now', '-600 days'), date('now', '+495 days')),
  ('MON-0115', '显示器', 'P2422H', '刘洋', '财务部', '已报废', date('now', '-2000 days'), date('now', '-905 days')),
  ('PRN-0003', '打印机', 'HP LaserJet M507', '行政部（公共）', '行政部', '在用', date('now', '-1000 days'), date('now', '+80 days')),
  ('SRV-0002', '服务器', 'PowerEdge R650', '研发部（公共）', '研发部', '在用', date('now', '-700 days'), date('now', '+395 days')),
  ('SRV-0005', '服务器', 'PowerEdge R740', '运维组（公共）', '研发部', '在用', date('now', '-1700 days'), date('now', '-240 days'));

INSERT INTO tickets VALUES
  ('T-24031', 'NB-0042', date('now', '-75 days'), date('now', '-72 days'), 'P2', '已转厂商', '键盘部分按键失灵，厂商上门更换键盘'),
  ('T-24107', 'NB-0042', date('now', '-6 days'), NULL, 'P2', '处理中', '键盘又有按键失灵，和上次是同一排键'),
  ('T-23988', 'NB-0057', date('now', '-130 days'), date('now', '-128 days'), 'P2', '已解决', '电池鼓包，更换电池（已过保，自费维修）'),
  ('T-24095', 'NB-0063', date('now', '-12 days'), NULL, 'P2', '已转厂商', '屏幕出现竖线，已送厂商检测'),
  ('T-23870', 'PC-0007', date('now', '-210 days'), date('now', '-209 days'), 'P3', '已解决', '开机慢，清理启动项后恢复'),
  ('T-24112', 'PC-0012', date('now', '-3 days'), NULL, 'P2', '处理中', '主板报错无法开机，已过保，等待维修报价'),
  ('T-24060', 'PRN-0003', date('now', '-40 days'), date('now', '-40 days'), 'P1', '已解决', '卡纸导致全楼层打印排队，清理定影组件'),
  ('T-24101', 'SRV-0005', date('now', '-9 days'), date('now', '-8 days'), 'P1', '已解决', '一块硬盘告警，已更换并重建阵列');
