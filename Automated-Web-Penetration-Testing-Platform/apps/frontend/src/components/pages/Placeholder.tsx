interface PlaceholderProps {
  title: string
  subtitle: string
  hint: string
}

export default function Placeholder({ title, subtitle, hint }: PlaceholderProps) {
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>{title}</h1>
          <p className="page-sub">{subtitle}</p>
        </div>
      </div>
      <div className="placeholder glass">
        <div className="placeholder-grid" />
        <div className="placeholder-content">
          <h2>{title} coming online</h2>
          <p>{hint}</p>
        </div>
      </div>
    </div>
  )
}
