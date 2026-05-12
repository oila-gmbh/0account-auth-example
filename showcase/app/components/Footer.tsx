const links = [
  { label: "Privacy", href: "https://0account.com/privacy/" },
  { label: "Terms & Conditions", href: "https://0account.com/terms-conditions/" },
  { label: "Imprint", href: "https://0account.com/imprint/" },
]

export default function Footer() {
  return (
    <footer className="mt-auto border-t border-zinc-800 py-4">
      <div className="flex items-center justify-center gap-6">
        {links.map(({ label, href }) => (
          <a
            key={label}
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-zinc-500 transition-colors hover:text-zinc-300"
          >
            {label}
          </a>
        ))}
      </div>
    </footer>
  )
}
