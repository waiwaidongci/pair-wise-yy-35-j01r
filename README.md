# 职业辐射剂量与异常事件

合并监测读数，比较历史剂量并管理超限调查、医学随访与报告期限。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链。
- `src/service.py`：权限检查、用例编排、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `src/seal.py`：审计完整性包的封装号、逐条摘要与原顺序重算校验（纯规则）。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8312
```

默认端口为`8312`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `GET /api/audit`
- `POST /api/audit/packages`，仅`admin`，提交`end_event_id`按结束事件生成完整性包
- `GET /api/audit/packages`
- `GET /api/audit/packages/{package_no}`
- `GET /api/audit/packages/{package_no}/verify`

允许角色：dosimetrist, radiation_officer, health_physicist, viewer, admin。剂量与调查水平之比决定升级程度，超过阈值必须进入调查；更正剂量不能覆盖已确认审计记录。

完整性包由结束事件派生封装号（`SEAL-00000000`），内含起止事件ID、起止摘要、条目数、逐条摘要与根摘要。同一结束事件重试沿用首次封装结果（响应带`reused`）。校验按封装时原顺序逐条重算：缺行、重排、内容改动均返回`ok:false`和`first_anomaly_event_id`；旧包只覆盖封装时的结束位置，之后新录事件不会混入。生成权限仅`admin`，查看与校验对审计角色开放。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
