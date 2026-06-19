export default function Radar({ active }: { active: boolean }) {
  return (
    <div className={`radar ${active ? 'radar-active' : ''}`}>
      <div className="radar-ring r1" />
      <div className="radar-ring r2" />
      <div className="radar-ring r3" />
      <div className="radar-ring r4" />
      <div className="radar-sweep" />
      <div className="radar-grid" />
      <div className="radar-center" />
    </div>
  )
}
