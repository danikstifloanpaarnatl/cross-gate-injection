# System One 多节点客服 Agent 与注入评测

这是本地可运行的研究 Agent。Jev 决策，固定 Python 代码执行路径；所有动作都是模拟记录。

- `agent.py`：固定问题、阈值、条件分支、最终动作复核。
- `fixtures.py`：6 开发 / 12 测试 / 4 正常关闭案例，以及 6 个附件注入候选。
- `provider.py`：Jev/OpenRouter 接口与隔离的离线 mock。
- `run.py`：开发选拔、冻结、封存测试和结果回放。
- `PROTOCOL.md`：精确威胁模型和成功判据。

运行 CLI 前先查看 `python run.py --help`。从本目录执行测试：

```bash
python -m unittest discover -s . -p 'test_*.py' -v
```

真实模型调用需要通过环境变量提供 `OPENROUTER_API_KEY`。不要把凭据写入脚本、命令历史或报告。没有可用凭据时只能运行离线软件检查，不能报告 Jev 攻击成功率。

官方依据：

- https://evals.typesafe.ai/customer_service
- https://docs.typesafe.ai/concepts/system-one
- https://docs.typesafe.ai/primitives/noul

## 离线流程与真实模型流程

```bash
# 仅软件冒烟；输出进入 results/mock，ASR 为 N/A。
python run.py --phase dev --mock --out results
python run.py --phase test --mock --out results
python run.py --phase replay --mock --out results

# 真实调用；先通过安全方式设置 OPENROUTER_API_KEY，输出进入 results/live。
python run.py --phase preflight --out results --max-calls 3 --max-cost 0.05
python run.py --phase dev --out results --max-calls 180 --max-cost 0.25
python run.py --phase test --out results --max-calls 117 --max-cost 0.20
python run.py --phase replay --out results
```

上述请求上限总和为 300，已返回费用阈值总和为 $0.50；任何阶段遇到错误均先检查报告，不继续把不完整结果当作完整测试。若费用字段缺失，上述金额不是已验证的账单上限，仍受请求次数硬上限约束。模型结果使用真实返回版本，测试必须与开发版本一致。每次新实验用不同的 `--out`，已有证据目录不能覆盖。

开发选择只使用 6 条开发案例，所选附件及代码哈希写入 `selection.json`。12 条测试案例不参与选择。若测试为 0 次成功，也原样报告，不修改问题或阈值来追求成功率。

## 已完成实测

参见 [REPORT.md](REPORT.md)。最终恢复测试位于 `results_completed/live/test`，中断运行保留在其他结果目录；总调用与费用必须跨目录合计。`resume_test.py` 只用于记录了来源与冻结哈希的恢复，不重新选择载荷。
