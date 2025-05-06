import { Facebook, Shield, Twitter, Youtube } from "lucide-react";
import Link from "next/link";
import Image from "next/image";
export default function Footer() {
  return (
    <>
      <footer className="border-t py-6 md:py-8 w-full">
        <div className="container mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col gap-4 md:flex-row md:gap-8">
            <div className="flex flex-col gap-2 md:gap-4 md:w-1/3">
              <div className="flex items-center gap-2 font-bold text-xl">
                <Link href="/" className="flex items-center">
                  <Image
                    src="/logo.png?height=61.970&width=245.089"
                    alt="Cybersecurity Training"
                    width={245.089}
                    height={61.97}
                    className="rounded-lg object-cover"
                    priority
                  />
                </Link>
              </div>
              <p className="text-sm text-muted-foreground">
                CamShield is Cambodia’s dedicated cybersecurity education and
                awareness platform.
              </p>
            </div>
            <div className="grid grid-cols-2 gap-4 md:gap-8 md:flex-1 lg:grid-cols-3">
              <div className="space-y-2">
                <h4 className="font-medium text-sm">Platform</h4>
                <ul className="space-y-2 text-sm">
                  <li>
                    <Link
                      href="#"
                      className="text-muted-foreground hover:text-foreground"
                    >
                      Courses
                    </Link>
                  </li>
                  <li>
                    <Link
                      href="#"
                      className="text-muted-foreground hover:text-foreground"
                    >
                      Pricing
                    </Link>
                  </li>
                  <li>
                    <Link
                      href="#"
                      className="text-muted-foreground hover:text-foreground"
                    >
                      FAQ
                    </Link>
                  </li>
                </ul>
              </div>
              <div className="space-y-2">
                <h4 className="font-medium text-sm">Company</h4>
                <ul className="space-y-2 text-sm">
                  <li>
                    <Link
                      href="#"
                      className="text-muted-foreground hover:text-foreground"
                    >
                      About
                    </Link>
                  </li>
                  <li>
                    <Link
                      href="#"
                      className="text-muted-foreground hover:text-foreground"
                    >
                      Blog
                    </Link>
                  </li>
                  <li>
                    <Link
                      href="#"
                      className="text-muted-foreground hover:text-foreground"
                    >
                      Careers
                    </Link>
                  </li>
                </ul>
              </div>
              <div className="space-y-2">
                <h4 className="font-medium text-sm">Legal</h4>
                <ul className="space-y-2 text-sm">
                  <li>
                    <Link
                      href="#"
                      className="text-muted-foreground hover:text-foreground"
                    >
                      Terms
                    </Link>
                  </li>
                  <li>
                    <Link
                      href="#"
                      className="text-muted-foreground hover:text-foreground"
                    >
                      Privacy
                    </Link>
                  </li>
                  <li>
                    <Link
                      href="#"
                      className="text-muted-foreground hover:text-foreground"
                    >
                      Cookies
                    </Link>
                  </li>
                </ul>
              </div>
            </div>
          </div>
          <div className="flex flex-col md:flex-row justify-between items-center gap-4 border-t mt-8 pt-8">
            <p className="text-xs text-muted-foreground">
              © {new Date().getFullYear()} CyberLearn. All rights reserved.
            </p>
            <div className="flex items-center gap-4">
              <Link
                href="https://www.facebook.com/cam.shield.2025#"
                className="text-muted-foreground hover:text-foreground"
                target="_blank"
              >
                <Facebook className="h-4 w-4" />
                <span className="sr-only">Facebook</span>
              </Link>
              <Link
                href="#"
                className="text-muted-foreground hover:text-foreground"
              >
                <Twitter className="h-4 w-4" />
                <span className="sr-only">Twitter</span>
              </Link>
              <Link
                href="#"
                className="text-muted-foreground hover:text-foreground"
              >
                <Youtube className="h-4 w-4" />
                <span className="sr-only">YouTube</span>
              </Link>
            </div>
          </div>
        </div>
      </footer>
    </>
  );
}
