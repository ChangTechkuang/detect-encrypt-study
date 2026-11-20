import type { StudyCase } from "./types";

// Written for a complete beginner: one idea per sentence, examples before explanations.
export const bcrypt: StudyCase = {
  id: "bcrypt",
  name: "bcrypt",
  fullName: "Blowfish-based crypt · a slow lock made for passwords (1999)",
  category: "hashing",
  tagline: "Locks a password so it can be checked but never read. Slow on purpose to stop guessing.",
  status: { label: "Recommended for passwords", tone: "good" },
  facts: [
    { label: "Result size", value: "Always 60 characters" },
    { label: "Turn it back?", value: "No, impossible" },
    { label: "Same password, same result?", value: "No, different every time" },
    { label: "Made", value: "1999" },
  ],
  java: "java/bcrypt/Bcrypt.java",

  analogy:
    "Like a lock that takes a second to open on purpose. Fine for you logging in once, hopeless for a thief trying a billion guesses.",
  terms: [
    { term: "Hash", meaning: "A one-way result. You can make it, but never turn it back." },
    { term: "Salt", meaning: "A random extra bit mixed in, so every result is different." },
    { term: "Cost", meaning: "How slow bcrypt is. Each +1 makes it twice as slow." },
  ],

  what: {
    summary: "bcrypt locks a password so a website can check it without storing it.",
    points: [
      "Slow on purpose, so guessing takes forever.",
      "Random salt → the same password gives a different result every time.",
      "No way back: from the result you can't get the password.",
    ],
  },

  how: {
    summary: "Think of a safe with a random code. Follow the password \"abc\" through bcrypt, one step at a time. Every value below is real.",
    steps: [
      {
        title: "Make a random salt",
        detail: "A salt is 16 random bytes that bcrypt picks fresh for every password. bcrypt writes those 16 bytes as 22 characters, using letters, digits, \".\" and \"/\". This salt is not secret: it is saved next to the result.",
        show: `password:  "abc"
salt:      If6bvum7DFjUnE9p2uDeDu

16 random bytes = 128 bits  →  written as 22 characters`,
      },
      {
        title: "Pick the cost",
        detail: "The cost says how slow bcrypt is. Cost 06 means 2 to the power 6 = 64 rounds of slow mixing. Each +1 doubles the rounds, so it doubles the time. Real websites use 10 or more; this example uses 06 to stay fast.",
        show: `cost 06  →  2⁶  = 2×2×2×2×2×2 = 64 rounds
cost 07  →  2⁷  = 128 rounds      (twice as slow)
cost 10  →  2¹⁰ = 1024 rounds     (16 times as slow as 06)`,
      },
      {
        title: "Mix password and salt slowly",
        detail: "bcrypt is built on Blowfish, a cipher (a machine that scrambles data with a key). Before Blowfish can scramble, it needs a setup: big tables of numbers made from the key. bcrypt builds that setup from the password and the salt, then rebuilds it again and again (64 rounds for cost 06), feeding in the password, then the salt, each time. This slow setup is the part that makes guessing expensive.",
        show: `setup ← "abc" + salt
repeat 64 times:            (cost 06 = 2⁶)
    setup ← mix in "abc"
    setup ← mix in salt`,
      },
      {
        title: "Scramble a fixed text 64 times",
        detail: "Now bcrypt takes a fixed 24-letter text, the same for everyone, and scrambles it with Blowfish using that setup, 64 times in a row. Only someone with the same password, salt and cost gets the same scrambled text. bcrypt keeps the first 23 bytes and writes them as 31 characters.",
        show: `text:    "OrpheanBeholderScryDoubt"   (24 bytes)
         scramble × 64 with the setup

result:  0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i   (23 bytes → 31 characters)`,
      },
      {
        title: "Save it all in one string",
        detail: "bcrypt puts everything needed to check the password later into one 60-character string. The password itself is not in it.",
        show: `$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i
└┬─┘└┬┘└─────────┬──────────┘└──────────────┬──────────────┘
 ①   ②           ③                          ④

① $2a$   = version of bcrypt
② 06     = cost (2⁶ = 64 rounds)
③ If6bvum7DFjUnE9p2uDeDu           = salt (22 characters)
④ 0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i  = result (31 characters)

4 + 3 + 22 + 31 = 60 characters`,
      },
      {
        title: "Same password, new salt",
        detail: "Lock \"abc\" again and bcrypt picks a new random salt. The whole result changes, even though the password is the same. So a thief can't spot two users with the same password, or use a ready-made list of results.",
        show: `salt If6bvum7DFjUnE9p2uDeDu  →  $2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i
salt Uhl01ewNiQzr1DaAFNWR.u  →  $2a$06$Uhl01ewNiQzr1DaAFNWR.ugut3vSpgL/2qlHxKSvGbBFJijgjzl7q`,
      },
    ],
  },

  where: {
    summary: "Only for saving passwords.",
    uses: [
      { place: "✓ Website logins", detail: "The server keeps only the bcrypt result, never your password." },
      { place: "✓ Apps and frameworks", detail: "A common default for passwords, e.g. Spring Security." },
      { place: "✗ Files & downloads", detail: "Too slow, and different each time. Use SHA-256." },
    ],
    example: {
      title: "The same password, locked twice",
      rows: [
        { label: "\"abc\" (1st time)", value: "$2b$06$fLWiHush/WH5S9YwUJ0Jfed7BLW9lPnb0r2Ny0Gqzg8beeWWKK0XO", mono: true },
        { label: "\"abc\" (2nd time)", value: "$2b$06$Uhl01ewNiQzr1DaAFNWR.ugut3vSpgL/2qlHxKSvGbBFJijgjzl7q", mono: true },
      ],
      note: "Same password, but the results are completely different. That's the random salt. ($2a$ and $2b$ are just two version names of bcrypt; both work the same.)",
    },
  },

  verify: {
    summary: "The result changes every time, so bcrypt reads the salt from the saved result and checks.",
    steps: [
      "You have the typed password and the saved result.",
      "Take the salt from the saved result and lock the password again.",
      "Same result → ✓ right password.",
      "Different result → ✗ wrong password.",
    ],
    example: {
      title: "Log in against the saved result",
      rows: [
        { label: "Saved result", value: "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i", mono: true },
        { label: "Typed \"abc\"", value: "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i → same", mono: true, tone: "ok" },
        { label: "Typed \"abd\"", value: "$2a$06$If6bvum7DFjUnE9p2uDeDunWZ8rKpaSl5Mxa4DS2y/aax5p5zB28S → different", mono: true, tone: "bad" },
      ],
      note: "Same salt (the start), but one letter changed (c → d), so login fails.",
    },
  },

  summary: {
    points: [
      "bcrypt = a slow, salted lock for passwords.",
      "Same password → a different result every time. You can't turn it back.",
      "Use it for passwords only. For files, use SHA-256.",
    ],
    algorithm: `saved = bcrypt("abc")          // $2a$06$If6bvum7DFjUnE9p2uDeDu0YHz...

// to check later:
if bcrypt(typed, salt from saved) == saved:
    ✓ right password
else:
    ✗ wrong password`,
  },
};
