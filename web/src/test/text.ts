/**
 * A Testing Library text matcher for text split over several elements: the
 * innermost element whose whole `textContent` is `text`. A command snippet
 * highlights its `<placeholders>` and a version greys its prerelease suffix
 * in spans of their own, which the default matcher (an element's own text
 * nodes) does not see as one string.
 */
export function textContent(text: string) {
  return (_content: string, element: Element | null): boolean =>
    element?.textContent === text &&
    Array.from(element.children).every((child) => child.textContent !== text)
}
