// Vitest setup for the signing suite.
//
// The signing tests generate real documents with `@bonniepdf/core`, and the
// core library requires the consuming application to declare which licence
// applies to it before the first document is generated. A test runner counts as
// a development environment, so without this declaration every test that builds
// a PDF to sign would throw. The suite is not production use, so `evaluation` is
// the honest declaration.
import { settings } from '@bonniepdf/core';

settings.license = 'evaluation';
