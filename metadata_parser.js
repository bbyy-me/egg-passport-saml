'use strict';

const xml2js = require('xml2js');

const parserConfig = {
  explicitRoot: true,
  explicitCharkey: true,
  tagNameProcessors: [xml2js.processors.stripPrefix]
};
const parser = new xml2js.Parser(parserConfig);
function getBindingLocation(serviceEl, bindingUri) {
  let location;
  if (serviceEl && serviceEl.length > 0) {
    serviceEl.forEach((element, index, array) => {
      if (element.$.Binding.toLowerCase() === bindingUri) {
        location = element.$.Location;
      }
    });
  }
  return location;
}

function getFirstCert(keyEl) {
  if (keyEl.KeyInfo &&
  keyEl.KeyInfo.length === 1 &&
  keyEl.KeyInfo[0].X509Data &&
  keyEl.KeyInfo[0].X509Data.length === 1 &&
  keyEl.KeyInfo[0].X509Data[0].X509Certificate &&
  keyEl.KeyInfo[0].X509Data[0].X509Certificate.length === 1) {
    return keyEl.KeyInfo[0].X509Data[0].X509Certificate[0]._;
  }
}

module.exports = async xml => new Promise((resolve, reject) => {
  parser.parseString(xml, (err, docEl) => {
    if (err) {
      return reject(err);
    }

    const metadata = {
      sso: {}, slo: {}, nameIdFormats: [], signingKeys: []
    };

    if (docEl.EntityDescriptor) {
      metadata.issuer = docEl.EntityDescriptor.$.entityID;

      if (docEl.EntityDescriptor.IDPSSODescriptor && docEl.EntityDescriptor.IDPSSODescriptor.length === 1) {
        metadata.protocol = 'samlp';

        const ssoEl = docEl.EntityDescriptor.IDPSSODescriptor[0];
        metadata.signRequest = ssoEl.$.WantAuthnRequestsSigned;

        ssoEl.KeyDescriptor.forEach((keyEl) => {
          if (keyEl.$.use && keyEl.$.use.toLowerCase() !== 'encryption') {
            metadata.signingKeys.push(getFirstCert(keyEl));
          }
        });

        if (ssoEl.NameIDFormat) {
          ssoEl.NameIDFormat.forEach((element, index, array) => {
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
