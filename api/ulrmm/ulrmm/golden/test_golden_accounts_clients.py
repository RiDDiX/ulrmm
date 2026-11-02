from ulrmm.golden import base


class TestGoldenAccountsClients(base.GoldenCase):
    area = "accounts-clients"


base.add_items(TestGoldenAccountsClients)
