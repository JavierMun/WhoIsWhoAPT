import type { EnrichmentOptions } from "../api/types";

export function EnrichmentFilterPanel({
  options,
  selectedSectors,
  selectedCountries,
  onSectorsChange,
  onCountriesChange,
  hint = "Hold Ctrl / ⌘ to select multiple.",
}: {
  options: EnrichmentOptions;
  selectedSectors: string[];
  selectedCountries: string[];
  onSectorsChange: (v: string[]) => void;
  onCountriesChange: (v: string[]) => void;
  hint?: string;
}) {
  const hasFilter = selectedSectors.length > 0 || selectedCountries.length > 0;

  function handleMultiSelect(
    event: React.ChangeEvent<HTMLSelectElement>,
    onChange: (v: string[]) => void
  ) {
    onChange(Array.from(event.target.selectedOptions, (opt) => opt.value));
  }

  return (
    <fieldset className="scope-selector" style={{ borderColor: hasFilter ? "#9bc5b9" : undefined }}>
      <legend style={{ display: "flex", alignItems: "center", gap: 8 }}>
        Enrichment filter
        {hasFilter ? (
          <button
            type="button"
            style={{ fontSize: "0.75rem", color: "#52606a", background: "none", border: "none", cursor: "pointer", padding: 0 }}
            onClick={() => { onSectorsChange([]); onCountriesChange([]); }}
          >
            Clear
          </button>
        ) : null}
      </legend>
      <p style={{ margin: "0 0 8px", fontSize: "0.82rem", color: "#52606a" }}>{hint}</p>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
        {options.sectors.length > 0 ? (
          <label className="field-group" style={{ margin: 0 }}>
            <span>Sectors</span>
            <select
              multiple
              size={5}
              value={selectedSectors}
              onChange={(e) => handleMultiSelect(e, onSectorsChange)}
              style={{ height: "auto", fontFamily: "inherit", fontSize: "0.85rem" }}
            >
              {options.sectors.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </label>
        ) : null}
        {options.countries.length > 0 ? (
          <label className="field-group" style={{ margin: 0 }}>
            <span>Countries</span>
            <select
              multiple
              size={5}
              value={selectedCountries}
              onChange={(e) => handleMultiSelect(e, onCountriesChange)}
              style={{ height: "auto", fontFamily: "inherit", fontSize: "0.85rem" }}
            >
              {options.countries.map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </label>
        ) : null}
      </div>
      {hasFilter ? (
        <p style={{ margin: "6px 0 0", fontSize: "0.8rem", color: "#2d6a4f" }}>
          {selectedSectors.length > 0 ? `Sectors: ${selectedSectors.join(", ")}` : ""}
          {selectedSectors.length > 0 && selectedCountries.length > 0 ? " · " : ""}
          {selectedCountries.length > 0 ? `Countries: ${selectedCountries.join(", ")}` : ""}
        </p>
      ) : null}
    </fieldset>
  );
}
