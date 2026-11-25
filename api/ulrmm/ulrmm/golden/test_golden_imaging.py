from ulrmm.golden import r3


class TestGoldenImaging(r3.R3Case):
    area = "imaging"


r3.add_items(TestGoldenImaging)
