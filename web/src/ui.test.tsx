import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { Glyph, Labelled } from "./ui";
import { partlyPassed } from "./visual";

it("renders a partly passed mark with a half fill, outline and accessible label", () => {
  const svg = renderToStaticMarkup(<Glyph enc={partlyPassed} />);
  expect(svg).toContain('aria-label="partly passed"');
  expect(svg).toContain("<title>partly passed</title>");
  expect(svg).toContain('class="half"');
  expect(svg).toContain('class="ring"');
  const legend = renderToStaticMarkup(<Labelled enc={partlyPassed} />);
  expect(legend).toContain("</svg> partly passed");
});
