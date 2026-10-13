package reexec

import "testing"

func TestExecutionPlanPreservesMissingStartAndRealReset(t *testing.T) {
	p := Plan{From: 25, To: 26, Heights: []Height{{Number: "25"}, {Number: "26"}}, Steps: []Step{
		{Run: "writer-a", Ordinal: 2, Height: "22", Number: "12", Input: "timer", Issues: []string{"missing_engine_start"}},
		{Run: "writer-a", Ordinal: 3, Height: "23", Number: "13", Input: "timer", Issues: []string{"missing_engine_start"}},
		{Run: "writer-a", Ordinal: 4, Height: "24", Number: "14", Input: "timer", Issues: []string{"missing_engine_start"}},
		{Run: "writer-a", Ordinal: 5, Height: "25", Number: "15", Input: "timer", Issues: []string{"missing_engine_start"}},
		{Run: "writer-b", Ordinal: 6, Height: "26", Number: "1", Input: "start", Issues: []string{}},
	}}
	x := planExecution(p, 2)
	if !x.bounded || x.from != 23 || x.compare != 25 || x.firstSelected != 2 || len(x.steps) != 4 || x.unavailable {
		t.Fatal(x)
	}
	if !x.steps[0].Approximate || !x.steps[0].Warmup || !x.steps[2].Approximate || x.steps[2].Warmup || x.steps[3].Approximate {
		t.Fatal(x.steps)
	}
	if !approximateComparable(x.steps[2]) {
		t.Fatal("available approximate input was lost")
	}
	s := x.steps[2]
	s.Issues = append(s.Issues, "missing_capture")
	if approximateComparable(s) {
		t.Fatal("missing bytes treated as approximate comparison")
	}
	closed := planExecution(p, 0)
	if closed.bounded || len(closed.steps) != 1 || closed.steps[0].Input != "start" {
		t.Fatal(closed)
	}
	p.Steps = p.Steps[2:]
	if !planExecution(p, 2).unavailable {
		t.Fatal("too little prefix accepted")
	}
}
