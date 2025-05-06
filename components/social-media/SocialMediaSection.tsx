import { Facebook, Twitter, Youtube } from "lucide-react";
import { BsTiktok } from "react-icons/bs";

export default function SocialMediaSection() {
  return (
    <>
      <section id="social" className="py-12 md:py-20 bg-muted/50 w-full">
        <div className="container mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col items-center justify-center space-y-4 text-center mb-10">
            <div className="space-y-2">
              <h2 className="text-3xl font-bold tracking-tighter sm:text-4xl md:text-5xl">
                Connect With Us
              </h2>
              <p className="max-w-[700px] text-muted-foreground md:text-xl">
                Follow us on social media for the latest updates, tips, and
                cybersecurity news.
              </p>
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
            <a
              href="https://www.facebook.com/cam.shield.2025"
              target="_blank"
              className="group flex flex-col items-center p-6 bg-background rounded-xl shadow-sm transition-all hover:shadow-md"
            >
              <div className="h-16 w-16 rounded-full bg-blue-100 flex items-center justify-center mb-4 group-hover:bg-blue-600 transition-colors">
                <Facebook className="h-8 w-8 text-blue-600 group-hover:text-white transition-colors" />
              </div>
              <h3 className="font-medium">Facebook</h3>
              <p className="text-sm text-muted-foreground mt-1">@CamShield</p>
            </a>

            <a
              href="#"
              className="group flex flex-col items-center p-6 bg-background rounded-xl shadow-sm transition-all hover:shadow-md"
            >
              <div className="h-16 w-16 rounded-full bg-red-100 flex items-center justify-center mb-4 group-hover:bg-red-600 transition-colors">
                <Youtube className="h-8 w-8 text-red-600 group-hover:text-white transition-colors" />
              </div>
              <h3 className="font-medium">YouTube</h3>
              <p className="text-sm text-muted-foreground mt-1">@CamShield</p>
            </a>

            <a
              href="#"
              className="group flex flex-col items-center p-6 bg-background rounded-xl shadow-sm transition-all hover:shadow-md"
            >
              <div className="h-16 w-16 rounded-full bg-black/10 flex items-center justify-center mb-4 group-hover:bg-black transition-colors">
                <Twitter className="h-8 w-8 text-black group-hover:text-white transition-colors" />
              </div>
              <h3 className="font-medium">X.com</h3>
              <p className="text-sm text-muted-foreground mt-1">@CamShield</p>
            </a>

            <a
              href="#"
              className="group flex flex-col items-center p-6 bg-background rounded-xl shadow-sm transition-all hover:shadow-md"
            >
              <div className="h-16 w-16 rounded-full bg-pink-100 flex items-center justify-center mb-4 group-hover:bg-pink-600 transition-colors">
                <BsTiktok style={{ fontSize: 28 }} />
              </div>
              <h3 className="font-medium">TikTok</h3>
              <p className="text-sm text-muted-foreground mt-1">@CamShield</p>
            </a>
          </div>
        </div>
      </section>
    </>
  );
}
