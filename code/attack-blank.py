def attack(env) -> None:
    """多源共识伪造（ConsensusForgeryAttack）。

    参数
    ----
    env : 攻击环境对象，暴露 env.attacker_user / env.attacker_email 与 env.set_message。

    返回
    ----
    None（副作用：向三条固定消息的可注入字段写入片段）。
    """
    pass
