'use strict';

const mock = require('egg-mock');

describe('test/passport-local.test.js', () => {
  let app;
  before(() => {
    app = mock.app({
      baseDir: 'apps/passport-local-test',
    });
    return app.ready();
  });

  after(() => app.close());
  afterEach(mock.restore);

  it('should ok', async () => {
    await app.httpRequest()
      .get('/passport/saml')
      .expect(302);
  });
});
