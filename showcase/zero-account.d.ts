// JSX type augmentation for the <zero-account> custom element.
// Placed in a .d.ts file to avoid @typescript-eslint/no-namespace errors in .tsx files.
declare module "react" {
  namespace JSX {
    interface IntrinsicElements {
      "zero-account": React.DetailedHTMLProps<
        React.HTMLAttributes<HTMLElement> & {
          "app-id"?: string
          "redirect-uri"?: string
          "finalize-uri"?: string
          scope?: string
          theme?: string
          environment?: string
          state?: string
          "with-button"?: boolean | ""
          mode?: string
          embedded?: boolean | ""
          "label-open-zero-account"?: string
          "label-download"?: string
          "label-sign-in-to"?: string
          "label-app-name"?: string
          "label-connection-failed"?: string
          "label-retry"?: string
          "label-encrypted-session"?: string
          "label-login-with-zero-account"?: string
          "label-qr-code-to-scan-with-mobile-app"?: string
          "label-close-modal"?: string
        },
        HTMLElement
      >
    }
  }
}
