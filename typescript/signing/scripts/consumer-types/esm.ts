// An ES module consumer of the public entry point, typechecked against dist/.
import { SignatureOptions, SigningAlgorithm, collectValidationMaterial, signPdf, type SignatureSettings } from '@bonniepdf/signing';

export const surface = [SignatureOptions, SigningAlgorithm, collectValidationMaterial, signPdf];
export type Settings = SignatureSettings;
