const LINE_PADDING_RULES = [
    1,
    // Add a new line after const, let, var declarations.
    { blankLine: "always", next: "*", prev: [ "const", "let", "var" ] },
    { blankLine: "any", next: [ "const", "let", "var" ], prev: [ "const", "let", "var" ] },
    // Add a new line after directive declarations like `use strict` etc.
    { blankLine: "always", next: "*", prev: "directive" },
    { blankLine: "any", next: "directive", prev: "directive" },
    // Add a new line before return statements.
    { blankLine: "always", next: "return", prev: "*" },
    // Add a new line try blocks.
    { blankLine: "always", next: "try", prev: "*" },
    // Add a new line break statements.
    { blankLine: "always", next: "break", prev: "*" },
    // Add a new line continue statements.
    { blankLine: "always", next: "continue", prev: "*" },
    // Add a new line before exports.
    { blankLine: "always", next: "export", prev: "*" },
    { blankLine: "any", next: "export", prev: "export" },
    // Add a new line before for loops.
    { blankLine: "always", next: "for", prev: "*" },
    // Add a new line before classes.
    { blankLine: "always", next: "class", prev: "*" },
    // Add a new line after import statements.
    { blankLine: "always", next: "*", prev: "import" },
    { blankLine: "any", next: "import", prev: "import" }
];

module.exports = {
    env: {
        node: true
    },
    extends: [
        "eslint:recommended"
    ],
    globals: {
        JSX: false,
        // no-undef complains about globalThis @see {@link https://github.com/eslint/eslint/issues/11553}
        globalThis: false
    },
    overrides: [
        {
            env: {
                node: true
            },
            extends: [
                "eslint:recommended",
                "plugin:@typescript-eslint/eslint-recommended",
                "plugin:@typescript-eslint/recommended"
            ],
            files: [ "**/*.ts" ],
            parser: "@typescript-eslint/parser",
            parserOptions: {
                ecmaVersion: 9,
                sourceType: "module"
            },
            rules: {
                "@typescript-eslint/ban-types": 1,
                "@typescript-eslint/explicit-function-return-type": 0,
                "@typescript-eslint/no-empty-function": [
                    "error",
                    {
                        allow: [ "constructors" ]
                    }
                ],
                "@typescript-eslint/no-explicit-any": 0,
                "@typescript-eslint/no-inferrable-types": "off",
                "@typescript-eslint/no-unused-vars": [
                    "warn",
                    {
                        argsIgnorePattern: "^_",
                        caughtErrorsIgnorePattern: "^_",
                        varsIgnorePattern: "^_"
                    }
                ],
                "@typescript-eslint/no-use-before-define": [
                    "warn",
                    {
                        classes: false,
                        functions: false,
                        typedefs: false,
                        variables: false
                    }
                ],
                "@typescript-eslint/no-var-requires": 0,
                "@typescript-eslint/padding-line-between-statements": [ ...LINE_PADDING_RULES ],
                "eol-last": "error",
                // In development, error level is set to `warn`. This will be overridden
                // by the production env linting config.
                "no-debugger": 1,
                // `no-undef` is discouraged in Typescript projects.
                // https://github.com/typescript-eslint/typescript-eslint/issues/2477#issuecomment-686892459
                "no-undef": 0,
                "no-use-before-define": "off",
                "padding-line-between-statements": "off"
            },
            settings: {
            }
        }
    ],
    parserOptions: {
        ecmaVersion: 9,
        sourceType: "module"
    },
    plugins: [ "import" ],
    root: true,
    rules: {
        "array-bracket-spacing": [ 1, "always" ],
        "comma-dangle": [ "warn", "never" ],
        "eol-last": "error",
        "import/order": [
            "warn",
            {
                alphabetize: {
                    caseInsensitive: true,
                    order: "asc"
                },
                groups: [ "builtin", "external", "index", "sibling", "parent", "internal" ]
            }
        ],
        indent: [
            1,
            4,
            {
                SwitchCase: 1
            }
        ],
        "jsx-quotes": [ "warn", "prefer-double" ],
        "lines-between-class-members": [
            1,
            "always",
            {
                exceptAfterSingleLine: true
            }
        ],
        "max-len": [
            "warn",
            {
                code: 120
            }
        ],
        "no-alert": 1,
        "no-console": "warn",
        "no-duplicate-imports": "warn",
        "no-restricted-imports": [
            "error",
            {
                paths: [
                    {
                        message: "Please use import foo from 'lodash-es/foo' instead.",
                        name: "lodash"
                    },
                    {
                        message: "Avoid using chain since it is non tree-shakable. Try out flow instead.",
                        name: "lodash-es/chain"
                    },
                    {
                        importNames: [ "chain" ],
                        message: "Avoid using chain since it is non tree-shakable. Try out flow instead.",
                        name: "lodash-es"
                    },
                    {
                        message: "Please use import foo from 'lodash-es/foo' instead.",
                        name: "lodash-es"
                    }
                ],
                patterns: [ "@wso2is/**/dist/**", "lodash/**", "lodash/fp/**" ]
            }
        ],
        "no-unreachable": "error",
        "object-curly-spacing": [ "warn", "always" ],
        "padding-line-between-statements": [ ...LINE_PADDING_RULES ],
        quotes: [ "warn", "double" ],
        semi: 1,
        "sort-imports": [
            "warn",
            {
                ignoreCase: false,
                ignoreDeclarationSort: true,
                ignoreMemberSort: false
            }
        ],
        "sort-keys": [
            "warn",
            "asc",
            {
                caseSensitive: true,
                minKeys: 2,
                natural: false
            }
        ]
    },
    settings: {
    }
};
