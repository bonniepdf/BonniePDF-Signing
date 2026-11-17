import { describe, it, expect, beforeAll } from 'vitest';
import { buildAgreement, buildSignedAgreement } from '../examples/signed-agreement';
import { buildCertificate, buildSealedCertificate } from '../examples/sealed-certificate';
import { createDemoPki, type DemoPki } from '../examples/support/demo-pki';
import { latin1Decode } from '../src/pdf';

let pki: DemoPki;

beforeAll(async () => {
  pki = await createDemoPki();
});

describe('the signed agreement demo', () => {
  it('places the signature over the box the layout reserved for it', async () => {
    const { rect } = await buildAgreement();
    const signed = latin1Decode(await buildSignedAgreement(pki));
    const [x, y, w, h] = rect;
    // The widget is the box's two corners, lower-left then upper-right.
    expect(signed).toContain(`/Rect [${x} ${y} ${x + w} ${y + h}]`);
    expect(signed).toContain('/BBox [0 0 ' + `${w} ${h}]`);
  });

  it('keeps the signature box on the page', async () => {
    const { rect } = await buildAgreement();
    const [x, y, w, h] = rect;
    expect(x).toBeGreaterThanOrEqual(0);
    expect(y).toBeGreaterThanOrEqual(0);
    expect(x + w).toBeLessThanOrEqual(595.28);
    expect(y + h).toBeLessThanOrEqual(841.89);
  });

  it('signs at PAdES baseline B with the signer named', async () => {
    const signed = latin1Decode(await buildSignedAgreement(pki));
    expect(signed).toContain('/SubFilter /ETSI.CAdES.detached');
    expect(signed).toContain('/Name (Alex Supplier)');
  });
});

describe('the sealed certificate demo', () => {
  it('places the seal over the box the layout reserved for it', async () => {
    const { rect } = await buildCertificate();
    const sealed = latin1Decode(await buildSealedCertificate(pki));
    const [x, y, w, h] = rect;
    expect(sealed).toContain(`/Rect [${x} ${y} ${x + w} ${y + h}]`);
  });

  it('carries the validation data that lets it verify offline', async () => {
    const sealed = latin1Decode(await buildSealedCertificate(pki));
    expect(sealed).toContain('/DSS');
    expect(sealed).toContain('/SubFilter /ETSI.CAdES.detached');
  });
});
