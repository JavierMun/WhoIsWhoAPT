import { ChevronDown, ChevronRight, FileSearch, Loader2, Search } from "lucide-react";
import { useState } from "react";

import { getReportTechniques, searchReports } from "../api/client";
import type { OpenCTIReport } from "../api/types";

interface Props {
  /** Called when the user confirms importing a report's techniques. */
  onImport: (reportName: string, techniqueIds: string[]) => void;
}

type ImporterState = "idle" | "searching" | "picked" | "fetching";

export function OpenCTIReportImporter({ onImport }: Props) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [state, setState] = useState<ImporterState>("idle");
  const [reports, setReports] = useState<OpenCTIReport[]>([]);
  const [pickedReport, setPickedReport] = useState<OpenCTIReport | null>(null);
  const [techniqueIds, setTechniqueIds] = useState<string[]>([]);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [fetchError, setFetchError] = useState<string | null>(null);

  async function handleSearch() {
    if (!query.trim()) return;
    setState("searching");
    setReports([]);
    setPickedReport(null);
    setTechniqueIds([]);
    setSearchError(null);
    setFetchError(null);
    try {
      const results = await searchReports(query.trim());
      setReports(results);
    } catch (err) {
      setSearchError(err instanceof Error ? err.message : "Search failed");
    } finally {
      setState("idle");
    }
  }

  async function handlePickReport(report: OpenCTIReport) {
    setPickedReport(report);
    setTechniqueIds([]);
    setFetchError(null);
    setState("fetching");
    try {
      const result = await getReportTechniques(report.id);
      setTechniqueIds(result.technique_ids);
      setState("picked");
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : "Failed to fetch techniques");
      setState("idle");
    }
  }

  function handleImport() {
    if (!pickedReport) return;
    onImport(pickedReport.name, techniqueIds);
    // Reset importer state
    setOpen(false);
    setQuery("");
    setReports([]);
    setPickedReport(null);
    setTechniqueIds([]);
    setState("idle");
    setSearchError(null);
    setFetchError(null);
  }

  return (
    <div style={{ borderTop: "1px solid #d9e0e3", paddingTop: 10 }}>
      <button
        type="button"
        className="secondary-action"
        onClick={() => setOpen((v) => !v)}
        style={{ width: "100%", justifyContent: "space-between" }}
        aria-expanded={open}
      >
        <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <FileSearch size={16} aria-hidden="true" />
          Import from OpenCTI report
        </span>
        {open ? <ChevronDown size={16} aria-hidden="true" /> : <ChevronRight size={16} aria-hidden="true" />}
      </button>

      {open ? (
        <div style={{ display: "grid", gap: 10, marginTop: 10 }}>
          {/* Search field */}
          <div className="field-group">
            <label htmlFor="report-search">Report name</label>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                id="report-search"
                type="search"
                placeholder="e.g. APT28 campaign 2023"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") void handleSearch();
                }}
                style={{ flex: 1, height: 40, border: "1px solid #cfd8dc", borderRadius: 6, padding: "0 10px", font: "inherit" }}
              />
              <button
                type="button"
                className="secondary-action refresh-action"
                onClick={() => void handleSearch()}
                disabled={state === "searching" || !query.trim()}
                aria-label="Search"
              >
                {state === "searching" ? (
                  <Loader2 size={16} aria-hidden="true" style={{ animation: "spin 1s linear infinite" }} />
                ) : (
                  <Search size={16} aria-hidden="true" />
                )}
              </button>
            </div>
          </div>

          {searchError ? (
            <p style={{ margin: 0, color: "#b42318", fontSize: "0.88rem" }}>{searchError}</p>
          ) : null}

          {/* Report list */}
          {reports.length > 0 ? (
            <div style={{ display: "grid", gap: 4 }}>
              <span style={{ fontSize: "0.82rem", color: "#52606a", fontWeight: 700, textTransform: "uppercase" }}>
                {reports.length} report{reports.length !== 1 ? "s" : ""} found
              </span>
              <ul style={{ margin: 0, padding: 0, listStyle: "none", display: "grid", gap: 4 }}>
                {reports.map((r) => (
                  <li key={r.id}>
                    <button
                      type="button"
                      onClick={() => void handlePickReport(r)}
                      disabled={state === "fetching"}
                      style={{
                        width: "100%",
                        textAlign: "left",
                        border: `1px solid ${pickedReport?.id === r.id ? "#9bc5b9" : "#d9e0e3"}`,
                        borderRadius: 6,
                        background: pickedReport?.id === r.id ? "#e8f2ef" : "#f7f9fa",
                        padding: "8px 10px",
                        cursor: "pointer",
                        font: "inherit",
                        fontSize: "0.88rem",
                      }}
                    >
                      <strong style={{ display: "block" }}>{r.name}</strong>
                      {r.published ? (
                        <span style={{ color: "#52606a", fontSize: "0.8rem" }}>
                          {new Date(r.published).toLocaleDateString()}
                        </span>
                      ) : null}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {reports.length === 0 && state === "idle" && query && !searchError ? (
            <p style={{ margin: 0, color: "#52606a", fontSize: "0.88rem" }}>No reports found.</p>
          ) : null}

          {/* Technique preview */}
          {state === "fetching" ? (
            <div style={{ display: "flex", alignItems: "center", gap: 8, color: "#52606a", fontSize: "0.88rem" }}>
              <Loader2 size={14} style={{ animation: "spin 1s linear infinite" }} aria-hidden="true" />
              Fetching techniques…
            </div>
          ) : null}

          {fetchError ? (
            <p style={{ margin: 0, color: "#b42318", fontSize: "0.88rem" }}>{fetchError}</p>
          ) : null}

          {state === "picked" && pickedReport ? (
            <div style={{ display: "grid", gap: 8 }}>
              <div style={{ border: "1px solid #d9e0e3", borderRadius: 6, padding: 10, background: "#f7f9fa" }}>
                <p style={{ margin: "0 0 4px", fontWeight: 700, fontSize: "0.9rem" }}>
                  {techniqueIds.length} technique{techniqueIds.length !== 1 ? "s" : ""} found
                </p>
                {techniqueIds.length > 0 ? (
                  <p style={{ margin: 0, color: "#52606a", fontSize: "0.82rem", wordBreak: "break-all" }}>
                    {techniqueIds.slice(0, 12).join(", ")}
                    {techniqueIds.length > 12 ? ` … +${techniqueIds.length - 12} more` : ""}
                  </p>
                ) : (
                  <p style={{ margin: 0, color: "#52606a", fontSize: "0.82rem" }}>
                    No ATT&CK techniques found in this report.
                  </p>
                )}
              </div>
              <button
                type="button"
                className="primary-action"
                onClick={handleImport}
                disabled={techniqueIds.length === 0}
                style={{ width: "100%" }}
              >
                Import as TTP profile
              </button>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
