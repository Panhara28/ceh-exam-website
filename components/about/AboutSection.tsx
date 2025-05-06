import Image from "next/image";
import { Button } from "../ui/button";
export default function AboutSection() {
  return (
    <>
      <section id="about" className="py-12 md:py-20 w-full">
        <div className="container mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="grid gap-6 lg:grid-cols-2 lg:gap-12 items-center">
            <div className="mx-auto lg:order-last">
              <Image
                src="/about.png?height=400&width=400"
                alt="About CyberLearn"
                width={400}
                height={400}
                className="rounded-lg object-cover"
              />
            </div>
            <div className="space-y-4">
              <h2 className="text-3xl font-bold tracking-tighter sm:text-4xl">
                About CamShield
              </h2>
              <p className="text-muted-foreground">
                CamShield is Cambodia’s dedicated cybersecurity education and
                awareness platform. Built by professionals with decades of
                combined industry experience, CamShield is on a mission to
                empower students, IT professionals, and organizations with the
                knowledge and tools needed to secure the digital future.
              </p>
              <p className="text-muted-foreground">
                At CamShield, we believe that cybersecurity starts with
                awareness. Our platform offers localized training, practical
                resources, and real-world case studies tailored to the unique
                challenges faced in Southeast Asia. Whether you're just
                beginning your journey or advancing your career, CamShield
                equips you to learn, secure, and protect—every step of the way.
              </p>
              <div className="flex flex-col sm:flex-row gap-3 pt-4">
                <Button variant="outline" size="lg">
                  Our Team
                </Button>
                <Button variant="ghost" size="lg">
                  Our Mission
                </Button>
              </div>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
