from ulrmm.golden import r3


class TestGoldenR3Agents(r3.R3Case):
    area = "r3-agents"


r3.add_items(TestGoldenR3Agents)
