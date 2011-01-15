
class Dict2XML:

    def __init__(self):
        self.xml = ""
        self.level = 0

    def __del__(self):
        pass

    def setXml(self,Xml):
        self.xml = Xml

    def setLevel(self,Level):
        self.level = Level

    def dict2xml(self, obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, dict):
                    if value:
                        self.xml += "\t" * self.level
                        self.xml += "<%s>\n" % (key,)
                        self.level += 1
                        self.dict2xml(value)
                        self.level -= 1
                        self.xml += "\t" * self.level
                        self.xml += "</%s>\n" % (key,)
                    else:
                        self.xml += "\t" * self.level
                        self.xml += "<%s></%s>\n" % (key, key)
                else:
                    self.xml += "\t" * self.level
                    self.xml += "<%s>%s</%s>\n" % (key, value, key)
        else:
            self.xml += "\t" * self.level
            self.xml += "<%s>%s</%s>\n" % (key, value, key)
        return self.xml

def createXML(dictionary, xml):
    xmlout = Dict2XML()
    xmlout.setXml(xml)
    return xmlout.dict2xml(dictionary)
