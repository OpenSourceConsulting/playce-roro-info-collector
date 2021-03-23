

import re

class RegxUtils():

    @classmethod
    def getString(cls, str):
        return re.sub(r"[^a-zA-Z0-9|\s]","", str)

