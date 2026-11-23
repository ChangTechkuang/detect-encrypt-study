import type { Category, StudyCase } from "./types";
import { md5 } from "./md5";
import { sha1 } from "./sha1";
import { sha256 } from "./sha256";
import { sha512 } from "./sha512";
import { bcrypt } from "./bcrypt";
import { des } from "./des";
import { tripledes } from "./tripledes";
import { aes } from "./aes";
import { seed } from "./seed";
import { aria } from "./aria";
import { chacha20 } from "./chacha20";
import { rsa } from "./rsa";
import { gongdong } from "./gongdong";

// Order inside each category = order on the home page.
export const CASES: StudyCase[] = [md5, sha1, sha256, sha512, bcrypt, des, tripledes, aes, seed, aria, chacha20, rsa, gongdong];

export const CATEGORIES: { id: Category; name: string; desc: string }[] = [
  { id: "hashing", name: "Hashing", desc: "Makes a fingerprint of data. You can't turn a fingerprint back into the data." },
  { id: "symmetric", name: "Symmetric encryption", desc: "Like a house key: the same secret key locks and unlocks." },
  { id: "asymmetric", name: "Asymmetric encryption", desc: "Like a mailbox: anyone can drop mail in (public key), only the owner can open it (private key)." },
];

export const caseById = (id: string) => CASES.find((c) => c.id === id);
