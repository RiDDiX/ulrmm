from ulrmm.golden import base


class TestGoldenLogs(base.GoldenCase):
    area = "logs"


base.add_items(TestGoldenLogs)
