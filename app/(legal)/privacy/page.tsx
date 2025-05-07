import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Metadata } from "next";

export default function PrivacyPage() {
  return (
    <>
      <section id="about" className="py-12 md:py-20 w-full">
        <div className="container mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="mb-8 space-y-4">
            <h1 className="text-4xl font-bold tracking-tight">
              Privacy Policy
            </h1>
            <p className="text-muted-foreground">
              Last updated: {new Date().toLocaleDateString()}
            </p>
          </div>

          <Card className="p-6 mb-8">
            <h2 className="text-2xl font-semibold mb-4">Introduction</h2>
            <p className="mb-4">
              Your privacy is important to us. This Privacy Policy explains how
              we collect, use, disclose, and safeguard your information when you
              visit our website.
            </p>
            <p>
              We reserve the right to make changes to this Privacy Policy at any
              time and for any reason. We will alert you about any changes by
              updating the "Last updated" date of this Privacy Policy.
            </p>
          </Card>

          <Card className="p-6 mb-8">
            <h2 className="text-2xl font-semibold mb-4">
              Information We Collect
            </h2>
            <h3 className="text-xl font-medium mb-2">Personal Data</h3>
            <p className="mb-4">
              We may collect personal information that you voluntarily provide
              to us when you register on our website, express interest in
              obtaining information about us or our products and services, or
              otherwise contact us.
            </p>
            <h3 className="text-xl font-medium mb-2">Derivative Data</h3>
            <p>
              Our servers automatically collect information when you access our
              website, such as your IP address, browser type, operating system,
              access times, and the pages you have viewed.
            </p>
          </Card>

          <Card className="p-6 mb-8">
            <h2 className="text-2xl font-semibold mb-4">
              How We Use Your Information
            </h2>
            <p className="mb-2">
              We may use the information we collect about you to:
            </p>
            <ul className="list-disc pl-6 mb-4 space-y-1">
              <li>Create and manage your account</li>
              <li>
                Deliver the type of content and product offerings you are
                interested in
              </li>
              <li>Improve our website and your user experience</li>
              <li>Comply with our legal obligations</li>
              <li>Respond to your inquiries and solve any potential issues</li>
            </ul>
          </Card>

          <Card className="p-6 mb-8">
            <h2 className="text-2xl font-semibold mb-4">
              Cookies and Web Beacons
            </h2>
            <p className="mb-4">
              We may use cookies, web beacons, tracking pixels, and other
              tracking technologies to help customize our website and improve
              your experience.
            </p>
            <p>
              Most browsers are set to accept cookies by default. You can remove
              or reject cookies, but be aware that such action could affect the
              availability and functionality of our website.
            </p>
          </Card>

          {/* <Card className="p-6 mb-8">
            <h2 className="text-2xl font-semibold mb-4">
              Third-Party Websites
            </h2>
            <p>
              Our website may contain links to third-party websites and
              applications of interest, including advertisements and external
              services. Once you have used these links to leave our website, any
              information you provide to these third parties is not covered by
              this Privacy Policy.
            </p>
          </Card>

          <Card className="p-6 mb-8">
            <h2 className="text-2xl font-semibold mb-4">Security</h2>
            <p>
              We use administrative, technical, and physical security measures
              to help protect your personal information. While we have taken
              reasonable steps to secure the personal information you provide to
              us, please be aware that no security measures are perfect or
              impenetrable.
            </p>
          </Card>

          <Card className="p-6 mb-8">
            <h2 className="text-2xl font-semibold mb-4">Contact Us</h2>
            <p className="mb-4">
              If you have questions or comments about this Privacy Policy,
              please contact us at:
            </p>
            <address className="not-italic mb-4">
              <div>Company Name</div>
              <div>123 Privacy Street</div>
              <div>City, State 12345</div>
              <div>Email: privacy@example.com</div>
            </address>
            <Button asChild>
              <Link href="/contact">Contact Us</Link>
            </Button>
          </Card> */}
        </div>
      </section>
    </>
  );
}

export const metadata: Metadata = {
  title: "Privacy | Learn. Secure. Protect.",
  description:
    "your trusted cybersecurity learning platform in Cambodia. We empower individuals and organizations with practical knowledge, training, and tools to defend against digital threats. Explore hands-on tutorials, up-to-date cybersecurity news, and expert guidance to stay secure in an ever-evolving digital world.",
  openGraph: {
    images: ["/cover.png"],
  },
};
