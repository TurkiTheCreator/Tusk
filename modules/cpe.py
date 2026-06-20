class CPEGenerator:

    def __init__(self):

        self.vendors = {

            "OpenSSH": "openbsd",
            "nginx": "nginx",
            "Apache": "apache",
            "vsFTPd": "vsftpd"

        }


    def generate_cpe(self, product, version):

        vendor = self.vendors.get(
            product,
            product.lower()
        )

        return (
            f"cpe:2.3:a:{vendor}:"
            f"{product.lower()}:{version}"
        )


    def generate_cpes(self, versions):

        cpes = {}

        for port, info in versions.items():

            product = info["product"]
            version = info["version"]

            if product != "unknown":

                cpes[port] = self.generate_cpe(
                    product,
                    version
                )

        return cpes
    
