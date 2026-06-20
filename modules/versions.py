import re


class VersionDetector:

    def extract_version(self, banner):

        patterns = [

            # OpenSSH
            (
                r"OpenSSH[_/]([\d\.]+)",
                "OpenSSH"
            ),

            # nginx
            (
                r"nginx[/ ]([\d\.]+)",
                "nginx"
            ),

            # Apache
            (
                r"Apache[/ ]([\d\.]+)",
                "Apache"
            ),

            # vsFTPd
            (
                r"vsFTPd[\s/]([\d\.]+)",
                "vsFTPd"
            )

        ]

        for pattern, product in patterns:

            match = re.search(
                pattern,
                banner,
                re.IGNORECASE
            )

            if match:

                return {

                    "product": product,
                    "version": match.group(1)

                }

        return {

            "product": "unknown",
            "version": "unknown"

        }


    def detect_versions(self, banners):

        versions = {}

        for port, banner in banners.items():

            versions[port] = self.extract_version(
                banner
            )

        return versions

