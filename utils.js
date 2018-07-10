'use strict';

const xml2js = require('xml2js');
const removeHeaders = cert => {
  const pem = /-----BEGIN (\w*)-----([^-]*)-----END (\w*)-----/g.exec(cert.toString());
  if (pem && pem.length > 0) {
    return pem[2].replace(/[\n|\r\n]/g, '');
  }
  return null;
};

const getMetadata = ({ host, entityID, cert }) => {
  entityID = entityID || host;
  const pem = removeHeaders(cert);
  return `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entityID}">
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>${pem}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>${pem}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${host}/passport/saml/logout"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${host}/passport/saml" index="1"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;
};

const parser = new xml2js.Parser({
  explicitRoot: true,
  explicitCharkey: true,
  tagNameProcessors: [ xml2js.processors.stripPrefix ],
});
const getBindingLocation = (serviceEl, bindingUri) => {
  let location;
  if (serviceEl && serviceEl.length > 0) {
    serviceEl.forEach((element) => {
      if (element.$.Binding.toLowerCase() === bindingUri) {
        location = element.$.Location;
      }
    });
  }
  return location;
};
const getFirstCert = (keyEl) => {
  if (keyEl.KeyInfo &&
  keyEl.KeyInfo.length === 1 &&
  keyEl.KeyInfo[0].X509Data &&
  keyEl.KeyInfo[0].X509Data.length === 1 &&
  keyEl.KeyInfo[0].X509Data[0].X509Certificate &&
  keyEl.KeyInfo[0].X509Data[0].X509Certificate.length === 1) {
    return keyEl.KeyInfo[0].X509Data[0].X509Certificate[0]._;
  }
};
const parserMetadata = async xml => {
  return new Promise((resolve, reject) => {
    parser.parseString(xml, (err, docEl) => {
      if (err) {
        return reject(err);
      }

      const metadata = {
        sso: {}, slo: {}, nameIdFormats: [], signingKeys: [],
      };

      if (docEl.EntityDescriptor) {
        metadata.issuer = docEl.EntityDescriptor.$.entityID;

        if (docEl.EntityDescriptor.IDPSSODescriptor && docEl.EntityDescriptor.IDPSSODescriptor.length === 1) {
          metadata.protocol = 'samlp';

          const ssoEl = docEl.EntityDescriptor.IDPSSODescriptor[0];
          metadata.signRequest = ssoEl.$.WantAuthnRequestsSigned;

          ssoEl.KeyDescriptor.forEach(keyEl => {
            if (keyEl.$.use && keyEl.$.use.toLowerCase() !== 'encryption') {
              metadata.signingKeys.push(getFirstCert(keyEl));
            }
          });

          if (ssoEl.NameIDFormat) {
            ssoEl.NameIDFormat.forEach((element) => {
              if (element._) {
                metadata.nameIdFormats.push(element._);
              }
            });
          }

          metadata.sso.redirectUrl = getBindingLocation(ssoEl.SingleSignOnService, 'urn:oasis:names:tc:saml:2.0:bindings:http-redirect');
          metadata.sso.postUrl = getBindingLocation(ssoEl.SingleSignOnService, 'urn:oasis:names:tc:saml:2.0:bindings:http-post');

          metadata.slo.redirectUrl = getBindingLocation(ssoEl.SingleLogoutService, 'urn:oasis:names:tc:saml:2.0:bindings:http-redirect');
          metadata.slo.postUrl = getBindingLocation(ssoEl.SingleLogoutService, 'urn:oasis:names:tc:saml:2.0:bindings:http-post');
        }
      }

      return resolve(metadata);
    });
  });
};

module.exports = {
  removeHeaders,
  getMetadata,
  parserMetadata,
};
