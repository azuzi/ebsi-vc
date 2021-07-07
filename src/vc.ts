import {
  VerifiableCredential,
  createVerifiableCredential,
  validateVerifiableCredential,
  resolveDid,
  createCredential,
  InputCredential,
  RequiredProof,
  SignatureValue,
} from "@cef-ebsi/verifiable-credential";

import {
  createPresentation,
  createVerifiablePresentation,
  validateVerifiablePresentation,
  validatePresentation,
  verifiableCredentialSchema,
} from "@cef-ebsi/verifiable-presentation";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { ethers } from "ethers";
import {
  createJWS,
  ES256KSigner,
  decodeJWT,
  createJWT,
} from "@cef-ebsi/did-jwt";
const base64url = require("base64url");


const tirUrl =
  "https://api.preprod.ebsi.eu/trusted-issuers-registry/v2/issuers";
const resolverUrl = "https://api.preprod.ebsi.eu/did-registry/v2/identifiers";
const privateKey =
  "61bcd3b7c3b8c0ab04baa2be1bb412e448fe5ac0a4338410980a9501eb1f11d7";

export const createVC = async () => {

  const did = "did:ebsi:51rzpDXXCtKExG47boFBahAgd2dtfAZbQxMHM17mYKoq";
  const requiredProof: RequiredProof = {
    type: "EcdsaSecp256k1Signature2019",
    proofPurpose: "assertionMethod",
    verificationMethod: `${did}#keys-1`,
  };

  const credential = createCredential(inputCredential);

  const signer = ES256KSigner(privateKey);
  
  const jws = await createJWS(
    credential.toString(),
    signer,
    { alg: "ES256K",typ:'JWT' },
    { canonicalize:true }
  );
  const jwtdata = await createJWT(
    credential,
    {
      alg: "ES256K",
      issuer: did,
      signer: signer,
      canonicalize: true,
    },
    {
      alg: "ES256K",
      typ: "JWT",
      kid: `${resolverUrl}/${did}#keys-1`,
    }
  );

  const vcToken = jwtdata.split(".");

  const signatureValue = {
    proofValue: `${vcToken[0]}..${vcToken[2]}`,
    proofValueName: "jws",
    iat: extractIatFromJwt(jwtdata),
  };

  const verifiableCredential = createVerifiableCredential(
    credential,
    requiredProof,
    signatureValue
  );
  const options = { tirUrl: tirUrl, resolver: resolverUrl };
  console.log(verifiableCredential);
  const result = await validateVerifiableCredential(
    verifiableCredential,
    options
  );
  console.log(result);
};

const extractIatFromJwt = (jwt) => {
  const token = jwt.split(".");
  const payload = base64url.decode(token[1]);
  return JSON.parse(payload).iat;
};

export const verifyVC = async () => {
  const did = vc.issuer;
  console.log("here");
  const tirUrl =
    "https://api.preprod.ebsi.eu/trusted-issuers-registry/v2/issuers";
  const resolverUrl = "https://api.preprod.ebsi.eu/did-registry/v2/identifiers";
  const options = { tirUrl: tirUrl, resolver: resolverUrl };
  //const didDoc = await resolveDid(did.toString(), resolverUrl);
  // await verifyEbsiJWT(jwt, {
  //   didRegistry: evaluateProof.resolver,
  // });
  let result = await validateVerifiableCredential(vc, options);
  console.log(result);
  result = await validateVerifiableCredential(vc2, options);
  console.log(result);
  result = await validateVerifiableCredential(vc3, options);
  console.log(result);
};

const inputCredential: InputCredential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://essif.europa.eu/schemas/vc/2020/v1",
  ],
  type: ["VerifiableCredential", "EssifVerifiableID"],
  issuer: "did:ebsi:51rzpDXXCtKExG47boFBahAgd2dtfAZbQxMHM17mYKoq",
  expirationDate: "2030-11-12T12:08:08.162Z",
  credentialSubject: {
    type: "Student",
    id: "did:key:z6Mki97ezMnXisk1iAyvVr4rJkNrWRBoR8f5viPJ62Jw6s98",
    studyProgram:
      "Master Studies in Strategy, Innovation, and Management Control",
    immatriculationNumber: "00000000",
    currentGivenName: "Eva",
    currentFamilyName: "Musterfrau",
    learningAchievement: "Master's Degree",
    dateOfBirth: "1999-10-22T00:00:00.000Z",
    dateOfAchievement: "2021-01-04T00:00:00.000Z",
    overallEvaluation: "passed with honors",
    eqfLevel: "http://data.europa.eu/snb/eqf/7",
    targetFrameworkName:
      "European Qualifications Framework for lifelong learning - (2008/C 111/01)",
  },
};

const vc: VerifiableCredential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://essif.europa.eu/schemas/vc/2020/v1",
  ],
  type: ["VerifiableCredential", "VerifiableAttestation", "DiplomaCredential"],
  issuer: "did:ebsi:51rzpDXXCtKExG47boFBahAgd2dtfAZbQxMHM17mYKoq",
  issuanceDate: "2021-07-06T09:17:25Z",
  credentialSubject: {
    type: "Student",
    id: "did:key:z6Mki97ezMnXisk1iAyvVr4rJkNrWRBoR8f5viPJ62Jw6s98",
    studyProgram:
      "Master Studies in Strategy, Innovation, and Management Control",
    immatriculationNumber: "00000000",
    currentGivenName: "Eva",
    currentFamilyName: "Musterfrau",
    learningAchievement: "Master's Degree",
    dateOfBirth: "1999-10-22T00:00:00.000Z",
    dateOfAchievement: "2021-01-04T00:00:00.000Z",
    overallEvaluation: "passed with honors",
    eqfLevel: "http://data.europa.eu/snb/eqf/7",
    targetFrameworkName:
      "European Qualifications Framework for lifelong learning - (2008/C 111/01)",
  },
  expirationDate: "2029-01-01T00:00:00Z",
  proof: {
    type: "EcdsaSecp256k1Signature2019",
    created: "2021-07-06T09:17:25Z",
    proofPurpose: "assertionMethod",
    verificationMethod:
      "did:ebsi:51rzpDXXCtKExG47boFBahAgd2dtfAZbQxMHM17mYKoq#keys-1",
    jws:
      "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJFUzI1NksifQ..MEQCIDN25mP8Kd1z60BUBgvCZKZsx7taGAlOjLyxddb1TeV2AiAobPYLWYP4R8gUGZglavXrQsQoLEipvthavMCmgu8Xow",
  },
};

const vc2: VerifiableCredential = {
  credentialSubject: {
    type: "Student",
    id: "did:ebsi:csapca8odx7vdpezz158sq7strxxvb3yxgq2uruawavz",
    studyProgram:
      "Master Studies in Strategy, Innovation, and Management Control",
    immatriculationNumber: "00000000",
    currentGivenName: "Eva",
    currentFamilyName: "Musterfrau",
    learningAchievement: "Master's Degree",
    dateOfBirth: "1999-10-22T00:00:00.000Z",
    dateOfAchievement: "2021-01-04T00:00:00.000Z",
    overallEvaluation: "passed with honors",
    eqfLevel: "http://data.europa.eu/snb/eqf/7",
    targetFrameworkName:
      "European Qualifications Framework for lifelong learning - (2008/C 111/01)",
  },
  issuer: "did:ebsi:51rzpDXXCtKExG47boFBahAgd2dtfAZbQxMHM17mYKoq",
  issuanceDate: "2021-07-05T08:12:56Z",
  expirationDate: "2021-07-12T08:12:56Z",
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://essif.europa.eu/schemas/vc/2020/v1",
  ],
  type: ["VerifiableCredential", "VerifiableAttestation", "DiplomaCredential"],
  proof: {
    type: "EcdsaSecp256k1Signature2019",
    created: "2021-07-05T08:17:56Z",
    proofPurpose: "assertionMethod",
    verificationMethod:
      "did:ebsi:51rzpDXXCtKExG47boFBahAgd2dtfAZbQxMHM17mYKoq#keys-1",
    jws:
      "eyJhbGciOiJFUzI1NksiLCJraWQiOiJodHRwczovL2FwaS5wcmVwcm9kLmVic2kuZXUvZGlkLXJlZ2lzdHJ5L3YyL2lkZW50aWZpZXJzL2RpZDplYnNpOjUxcnpwRFhYQ3RLRXhHNDdib0ZCYWhBZ2QyZHRmQVpiUXhNSE0xN21ZS29xI2tleXMtMSIsInR5cCI6IkpXVCJ9..kvU3fl4zHQfICsGIIE4upezg74WbXc4ESB4mLZPWtdFKHERFqsVLv_SDXCOu27iEj8cFEIrjvUqZBv_Aw0XTTw",
  },
};

const vc3: VerifiableCredential = {
  issuer: "did:ebsi:51rzpDXXCtKExG47boFBahAgd2dtfAZbQxMHM17mYKoq",
  credentialSubject: {
    type: "Student",
    id: "did:key:z6Mki97ezMnXisk1iAyvVr4rJkNrWRBoR8f5viPJ62Jw6s98",
    studyProgram:
      "Master Studies in Strategy, Innovation, and Management Control",
    immatriculationNumber: "00000000",
    currentGivenName: "Eva",
    currentFamilyName: "Musterfrau",
    learningAchievement: "Master's Degree",
    dateOfBirth: "1999-10-22T00:00:00.000Z",
    dateOfAchievement: "2021-01-04T00:00:00.000Z",
    overallEvaluation: "passed with honors",
    eqfLevel: "http://data.europa.eu/snb/eqf/7",
    targetFrameworkName:
      "European Qualifications Framework for lifelong learning - (2008/C 111/01)",
  },
  issuanceDate: "2021-07-06T15:33:37Z",
  expirationDate: "2030-11-12T12:08:08Z",
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://essif.europa.eu/schemas/vc/2020/v1",
  ],
  type: ["VerifiableCredential", "EssifVerifiableID"],
  proof: {
    type: "EcdsaSecp256k1Signature2019",
    created: "2021-07-06T15:33:37Z",
    proofPurpose: "assertionMethod",
    verificationMethod:
      "did:ebsi:51rzpDXXCtKExG47boFBahAgd2dtfAZbQxMHM17mYKoq#keys-1",
    jws:
      "eyJhbGciOiJFUzI1NksiLCJraWQiOiJodHRwczovL2FwaS5wcmVwcm9kLmVic2kuZXUvZGlkLXJlZ2lzdHJ5L3YyL2lkZW50aWZpZXJzL2RpZDplYnNpOjUxcnpwRFhYQ3RLRXhHNDdib0ZCYWhBZ2QyZHRmQVpiUXhNSE0xN21ZS29xI2tleXMtMSIsInR5cCI6IkpXVCJ9..1bYhCB3XRIrGj1Cr4AObca-mXz3jCgu7Sg8IFx3Km1S2T8A72X1aATo9ktfjLVDEepDPmMSOTGjaQf2Wez2tXA",
  },
};
