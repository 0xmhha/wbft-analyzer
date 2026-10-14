package scenario

import "testing"

func TestSyntheticExecutionDoesNotProveSourceCoverage(t *testing.T) {
	nodes, links := completeFixture()
	runtime := []Runtime{}
	for _, n := range nodes {
		runtime = append(runtime, Runtime{Node: n.Address.Hex(), Starts: 1, SignFloorState: "none"})
	}
	app := AppTiming{Build: []AppSample{}, Import: []AppSample{}}
	for _, node := range nodes {
		app.Policies = append(app.Policies, declaredApplicationPolicy(node.Address.Hex(), "r", 1))
		app.Build = append(app.Build, AppSample{Node: node.Address.Hex(), Nanoseconds: 1})
		app.Import = append(app.Import, AppSample{Node: node.Address.Hex(), Nanoseconds: 1})
	}
	got, err := Assess(nodes, links, runtime, app)
	if err != nil || got.Status != "complete" {
		t.Fatalf("synthetic %+v %v", got, err)
	}
	links[0].Status = "partial"
	runtime[0].StartNS = 1
	app.Unproved = 1
	got, err = Assess(nodes, links, runtime, app)
	if err != nil || got.Status != "partial" || len(got.Issues) != 2 {
		t.Fatalf("source gaps %+v %v", got, err)
	}
}

func TestAssessmentDoesNotAcceptDuplicateLinkModels(t *testing.T) {
	nodes, links := completeFixture()
	links[1] = links[0]
	if _, err := Assess(nodes, links, nil, AppTiming{}); err == nil {
		t.Fatal("duplicate directed link counted as coverage")
	}
}
