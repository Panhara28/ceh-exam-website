import Link from "next/link";
import { Button } from "../ui/button";
import Image from "next/image";

export default function HeroSection() {
  return (
    <>
      <section className="py-12 md:py-20 w-full">
        <div className="container mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="grid gap-6 lg:grid-cols-2 lg:gap-12 items-center">
            <div className="space-y-4">
              <h1 className="text-3xl font-bold tracking-tighter sm:text-4xl md:text-5xl bg-gradient-to-r from-[#2071f8] to-[#d43636] text-transparent bg-clip-text">
                Master Cybersecurity Skills with Expert-Led Courses
              </h1>
              <p className="md:text-xl bg-gradient-to-r from-[#d35f5f]/80 to-[#2a7aff]/80 text-transparent bg-clip-text font-medium">
                Gain practical knowledge in digital forensics and ethical
                hacking through our comprehensive courses designed for all skill
                levels.
              </p>
              <div className="flex flex-col sm:flex-row gap-3">
                <Link
                  href="/learning"
                  className="inline-flex items-center justify-center gap-2 whitespace-nowrap text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 bg-primary text-primary-foreground hover:bg-primary/90 h-11 rounded-md px-8 w-full sm:w-auto bg-gradient-to-r from-[#2071f8] to-[#d43636] hover:from-[#c55555] hover:to-[#2569e8] border-0"
                >
                  Learn More
                </Link>
                <Link
                  href="/preparations"
                  className="inline-flex items-center justify-center gap-2 whitespace-nowrap text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 border bg-background hover:text-accent-foreground h-11 rounded-md px-8 w-full sm:w-auto border-[#2a7aff] text-[#2a7aff] hover:bg-[#2a7aff]/10"
                >
                  View Pre-Exam
                </Link>
              </div>
            </div>
            <div className="mx-auto lg:ml-auto">
              <Image
                src="/hero-image-1.png?height=1228.990&width=1210.522"
                alt="Cybersecurity Training"
                width={1210.522}
                height={1228.99}
                className="rounded-lg object-cover"
                priority
              />
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
