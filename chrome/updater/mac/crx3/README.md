Generate signed CRX3 package for updater

Add a CRX3 signing action that generates chromium.crx3
from the packaged ZIP archive and update the packaging
target to depend on the signed CRX3 output.

Before building the chromium_crx3 target, generate the
signing key:

openssl genrsa 4096 | openssl pkcs8
-inform PEM -nocrypt -topk8 -outform DER
-out chrome/updater/mac/crx3/chromium_crx3.pkcs8.der
