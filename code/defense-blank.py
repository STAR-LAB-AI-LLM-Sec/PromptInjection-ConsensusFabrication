def defend(env, stage: str, tool_name: str, tool_input: dict, tool_output, call_history: list):
    """多源共识来源校验中介（ConsensusSourceGuard）。

    参数
    ----
    env           : 评测环境对象（守方视图，不含攻击锚点）
    stage         : "pre"（工具执行前）或 "post"（工具执行后）
    tool_name     : 当前工具名称
    tool_input    : 工具参数 dict
    tool_output   : pre 阶段恒为 None；post 阶段为工具真实返回值
    call_history  : 本次会话已完成的工具调用序列（output 为最终内容）

    返回
    ----
    pre 阶段：True=放行 / False=阻断 / dict=改写参数；
    post 阶段：True 或 None=原样返回 / False=清空 / 同类型值=净化改写。
    """
    pass
