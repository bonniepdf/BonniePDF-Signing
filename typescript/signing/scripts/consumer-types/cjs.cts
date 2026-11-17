// A CommonJS consumer of the public entry point, typechecked against dist/.
// `.cts` makes it CommonJS, so the import resolves through the `require`
// condition to the `.d.cts` declarations.
import { SignatureOptions, SigningAlgorithm, collectValidationMaterial, signPdf, type SignatureSettings } from '@bonniepdf/signing';

export const surface = [SignatureOptions, SigningAlgorithm, collectValidationMaterial, signPdf];
export type Settings = SignatureSettings;
