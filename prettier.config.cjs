module.exports = {
  printWidth: 120,
  semi: false,
  singleQuote: true,
  trailingComma: 'all',
  plugins: ['prettier-plugin-astro', 'prettier-plugin-tailwindcss'],
  pluginSearchDirs: false,
  overrides: [
    {
      files: ['apps/web/**/*.astro'],
      options: {
        parser: 'astro',
      },
    },
  ],
}
