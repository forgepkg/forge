# The Forge design system in the web UI

`components/ui/` holds the design system's components, typed for the app.
They render the `fg-*` classes of [`styles/forge-ui.css`](../../styles/forge-ui.css)
and draw every value from the tokens in [`styles/tokens.css`](../../styles/tokens.css).
Import them from `~/components/ui`.

## Foundations

- **Colour.** The page is `ground`; content sits in `surface` panels edged with
  `line`. Text is `ink` (names, values), `ink-muted` (descriptions, secondary
  cells) or `ink-faint` (placeholders, separators). Forge orange (`heat`) is
  the only accent: the primary button, links, the selected tab, focus. Kinds
  have their own colours (`hosted` blue, `proxy` teal, `group` violet), used
  only by `KindBadge` and the rail's dots. States (`ok`, `warn`, `danger`)
  always come with a word.
- **Tailwind.** `styles.css` maps the tokens into Tailwind's theme and turns
  the stock palette off: use `bg-surface`, `text-ink-muted`, `border-line`,
  `text-danger` for the odd one-off, and layout utilities (`flex`, `gap-4`,
  `grid`) freely. Prefer a component or an `fg-*` class over utilities for
  anything a component already draws.
- **Type.** IBM Plex Sans for the interface, JetBrains Mono (`font-mono`,
  `mono` props) for versions, digests, URLs, token names and commands.
- **Themes.** `data-theme` on `<html>`: `light`, `dark-rail` (dark rail and
  code blocks on light content) and `dark`; `lib/theme.ts` owns it.

## Writing a screen

Every screen is a `Page`: a `PageHeader` (breadcrumbs, the one title, a
description, kind and format badges, facts, actions on the right), then
`Panel`s, one column, 24px apart. Detail screens put install commands and
facts in a side column with `Columns aside={…}`; overview numbers go in a
`StatRow` of `Stat`s above the panels.

- **Lists** are a `Table` in a `flush` `Panel`, with a `Toolbar` (search,
  filters) above it and a `Paginator` under it. The first cell is the row's
  name (`lead`), a `fg-link-strong` link with an optional sub-line
  (`CellStack`). Row actions are small ghost buttons in `CellActions`, or a
  `Menu` when there are more than two.
- **Forms** are panels too (`Panel as="form"`, buttons in `footer` or a
  `FormActions` row): `TextField`, `SelectField`, `TextareaField`,
  `Checkbox`, `Switch` (a setting that stands alone), `RadioGroup`, and
  `ChoiceCards` for a decision that shapes everything after it. A field's
  description says what the value does; its `error` what is wrong.
- **Feedback.** `Notice` for a message where the problem is (an error is
  `tone="danger"`), `EmptyState` for nothing yet / nothing matches / no
  access, `Skeleton` on first loads, `useToast()` after a save, `Dialog` to
  confirm what cannot be undone (`confirmVariant="danger-solid"`, the button
  naming the object).
- **Code.** `CommandSnippet` (one command; `<placeholders>` are highlighted),
  `CodeBlock` (a file), `CopyField` (a URL), `SecretOnce` (a new token),
  `Code` (inline).
- **Words.** Sentence case for every label ("New repository"); status words
  lowercase (`available`, `offline`, `revoked`); no exclamation marks, no
  emoji. Name the consequence of a destructive action, then the fix.
