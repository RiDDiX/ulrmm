from ulrmm.golden import r3


class TestGoldenR3AlertsChecksTasks(r3.R3Case):
    area = "r3-alerts-checks-tasks"


r3.add_items(TestGoldenR3AlertsChecksTasks)
