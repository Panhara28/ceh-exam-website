import TermsSection from "@/components/terms/term";
import { Metadata } from "next";

export default function TermPage() {
  return <TermsSection />;
}

export const metadata: Metadata = {
  title: "Term | Learn. Secure. Protect.",
  description:
    "your trusted cybersecurity learning platform in Cambodia. We empower individuals and organizations with practical knowledge, training, and tools to defend against digital threats. Explore hands-on tutorials, up-to-date cybersecurity news, and expert guidance to stay secure in an ever-evolving digital world.",
  openGraph: {
    images: ["/cover.png"],
  },
};
