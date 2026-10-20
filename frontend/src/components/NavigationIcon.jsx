const paths = {
  overview: ["M3 3h7v7H3z", "M14 3h7v7h-7z", "M3 14h7v7H3z", "M14 14h7v7h-7z"],
  devices: ["M7 7h10v10H7z", "M10 10h4v4h-4z", "M9 3v4m6-4v4M9 17v4m6-4v4M3 9h4m-4 6h4m10-6h4m-4 6h4"],
  logs: ["M6 3h9l4 4v14H5V3h1Z", "M14 3v5h5", "M8 12h8m-8 4h6"],
  events: ["m12 3 10 18H2L12 3Z", "M12 9v5m0 3h.01"],
  isolation: ["M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7l-9-4Z", "M9 11h6v6H9z", "M10 11V9a2 2 0 0 1 4 0v2"],
  traffic: ["M3 3v18h18", "m6 15 4-5 4 3 6-8"],
  gateway: ["M3 3h18v7H3z", "M3 14h18v7H3z", "M7 6.5h.01m0 11h.01M11 6.5h6m-6 11h6"],
};

export default function NavigationIcon({ name }) {
  return (
    <svg className="navigation-icon" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"
      aria-hidden="true" focusable="false">
      {paths[name].map((d) => <path key={d} d={d} />)}
    </svg>
  );
}
