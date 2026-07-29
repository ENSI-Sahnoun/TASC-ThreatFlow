import * as echarts from 'echarts';
import { feature } from 'topojson-client';

let registered: Promise<void> | null = null;

// world-atlas's topology ids are ISO 3166-1 numeric codes (as strings). The API deals only in
// ISO-2 (region/country codes from /api/stats/dashboard and /api/facets), so this table is the
// single bridge between the two standards — built and verified against the actual
// countries-110m.json feature list, not typed from memory. Codes absent here (e.g. AD, HK) are
// genuinely absent from the low-resolution 110m atlas: micro-states and city territories have no
// polygon to shade regardless of what this table says, so there is nothing to add for them.
export const ISO2_TO_ID: Record<string, string> = {
  AF: '004', AL: '008', DZ: '012', AO: '024', AQ: '010', AR: '032', AM: '051', AU: '036',
  AT: '040', AZ: '031', BS: '044', BD: '050', BY: '112', BE: '056', BZ: '084', BJ: '204',
  BT: '064', BO: '068', BA: '070', BW: '072', BR: '076', BN: '096', BG: '100', BF: '854',
  BI: '108', KH: '116', CM: '120', CA: '124', CF: '140', TD: '148', CL: '152', CN: '156',
  CO: '170', CG: '178', CR: '188', CI: '384', HR: '191', CU: '192', CY: '196', CZ: '203',
  CD: '180', DK: '208', DJ: '262', DO: '214', EC: '218', EG: '818', SV: '222', GQ: '226',
  ER: '232', EE: '233', SZ: '748', ET: '231', FK: '238', FJ: '242', FI: '246', TF: '260',
  FR: '250', GA: '266', GM: '270', GE: '268', DE: '276', GH: '288', GR: '300', GL: '304',
  GT: '320', GN: '324', GW: '624', GY: '328', HT: '332', HN: '340', HU: '348', IS: '352',
  IN: '356', ID: '360', IR: '364', IQ: '368', IE: '372', IL: '376', IT: '380', JM: '388',
  JP: '392', JO: '400', KZ: '398', KE: '404', KW: '414', KG: '417', LA: '418', LV: '428',
  LB: '422', LS: '426', LR: '430', LY: '434', LT: '440', LU: '442', MK: '807', MG: '450',
  MW: '454', MY: '458', ML: '466', MR: '478', MX: '484', MD: '498', MN: '496', ME: '499',
  MA: '504', MZ: '508', MM: '104', NA: '516', NP: '524', NL: '528', NC: '540', NZ: '554',
  NI: '558', NE: '562', NG: '566', KP: '408', NO: '578', OM: '512', PK: '586', PS: '275',
  PA: '591', PG: '598', PY: '600', PE: '604', PH: '608', PL: '616', PT: '620', PR: '630',
  QA: '634', RO: '642', RU: '643', RW: '646', SS: '728', SA: '682', SN: '686', RS: '688',
  SL: '694', SK: '703', SI: '705', SB: '090', SO: '706', ZA: '710', KR: '410', ES: '724',
  LK: '144', SD: '729', SR: '740', SE: '752', CH: '756', SY: '760', TW: '158', TJ: '762',
  TZ: '834', TH: '764', TL: '626', TG: '768', TT: '780', TN: '788', TR: '792', TM: '795',
  UG: '800', UA: '804', AE: '784', GB: '826', US: '840', UY: '858', UZ: '860', VU: '548',
  VE: '862', VN: '704', EH: '732', YE: '887', ZM: '894', ZW: '716',
};

type Ring = [number, number][];
type Polygon = Ring[];
type Geometry =
  | { type: 'Polygon'; coordinates: Polygon }
  | { type: 'MultiPolygon'; coordinates: Polygon[] }
  | { type: string; coordinates: unknown };

// topojson-client's arc reconstruction leaves a handful of countries (Russia, Fiji — anything
// whose real coastline straddles ±180°) with a ring that quietly jumps from ~+179° to ~-180°
// between two adjacent points instead of stopping at the edge. Plotted with the map's plain
// lon=x/lat=y projection, that "jump" is just a straight line between the two points — which
// spans the entire map width as one long horizontal streak. Antarctica's own band lower on the
// map is real coastline data genuinely sweeping the full longitude range at a polar latitude, not
// this bug, so it's deliberately left untouched (there's no single-segment jump to cut there).
// The fix used here is the standard antimeridian cut: wherever one step's longitude delta implies
// crossing the dateline, split the ring there rather than draw the connecting segment.
function splitAntimeridian(ring: Ring): Ring[] {
  const pieces: Ring[] = [];
  let current: Ring = [ring[0]];
  for (let i = 1; i < ring.length; i++) {
    const prev = ring[i - 1];
    const pt = ring[i];
    if (Math.abs(pt[0] - prev[0]) > 180) {
      pieces.push(current);
      current = [pt];
    } else {
      current.push(pt);
    }
  }
  pieces.push(current);
  // A fragment with fewer than 3 points can't close into a valid ring — drop it rather than let
  // echarts choke on a degenerate polygon.
  return pieces.filter((p) => p.length >= 3).map((p) => {
    const first = p[0];
    const last = p[p.length - 1];
    return first[0] === last[0] && first[1] === last[1] ? p : [...p, first];
  });
}

// Cutting only ever needs to look at the outer ring — none of the countries affected here carry
// holes, so every split fragment becomes its own single-ring polygon rather than trying to
// re-associate it with sibling hole rings.
function splitPolygon(polygon: Polygon): Polygon[] {
  const out: Polygon[] = [];
  for (const ring of polygon) for (const piece of splitAntimeridian(ring)) out.push([piece]);
  return out;
}

function fixAntimeridian(geometry: Geometry): void {
  if (geometry.type === 'Polygon') {
    const polys = splitPolygon(geometry.coordinates as Polygon);
    if (polys.length > 1) {
      (geometry as { type: string }).type = 'MultiPolygon';
      (geometry as { coordinates: unknown }).coordinates = polys;
    } else if (polys.length === 1) {
      (geometry as { coordinates: unknown }).coordinates = polys[0];
    }
  } else if (geometry.type === 'MultiPolygon') {
    const out: Polygon[] = [];
    for (const polygon of geometry.coordinates as Polygon[]) out.push(...splitPolygon(polygon));
    (geometry as { coordinates: unknown }).coordinates = out;
  }
}

// world-atlas ships no map data. world-atlas is TopoJSON, which is far smaller than the
// equivalent GeoJSON — we convert once, lazily, and only for pages that draw the map.
export function ensureWorldMap(): Promise<void> {
  if (!registered) {
    registered = import('world-atlas/countries-110m.json').then((mod) => {
      const topo = (mod as { default: unknown }).default ?? mod;
      const geo = feature(topo as never, (topo as never as { objects: { countries: never } }).objects.countries) as unknown as {
        features: { id?: string; properties?: Record<string, unknown>; geometry: Geometry }[];
      };
      // echarts' map series joins series data to regions by the "name" property, not by the
      // topology's numeric id. We overwrite name with the id here so every further lookup —
      // series data, click events, tooltips — can work in one currency: the ISO-3166-1 numeric
      // code, translated at the edges via ISO2_TO_ID above.
      for (const f of geo.features) {
        f.properties = { ...f.properties, name: f.id };
        fixAntimeridian(f.geometry);
      }
      echarts.registerMap('world', geo as never);
    });
  }
  return registered;
}
