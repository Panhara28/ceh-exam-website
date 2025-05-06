import Image from "next/image";
import Link from "next/link";
import {
  Facebook,
  Youtube,
  Twitter,
  Bookmark,
  Shield,
  FileText,
  ChevronDown,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export default function Home() {
  return (
    <div className="flex flex-col min-h-screen">
      {/* Navigation */}
      <header className="border-b sticky top-0 z-50 bg-background">
        <div className="container flex h-16 items-center justify-between">
          <div className="flex items-center gap-2 font-bold text-xl">
            <Shield className="h-6 w-6 text-primary" />
            <span>CamShield</span>
          </div>
          <nav className="hidden md:flex items-center gap-6">
            <Link href="/" className="text-sm font-medium hover:text-primary">
              Home
            </Link>
            <Link
              href="#about"
              className="text-sm font-medium hover:text-primary"
            >
              About Us
            </Link>
            <Link
              href="#social"
              className="text-sm font-medium hover:text-primary"
            >
              Social Media
            </Link>
            <DropdownMenu>
              <DropdownMenuTrigger className="flex items-center gap-1 text-sm font-medium hover:text-primary">
                Learning <ChevronDown className="h-4 w-4" />
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem>
                  <Link href="#forensic" className="w-full">
                    Forensic
                  </Link>
                </DropdownMenuItem>
                <DropdownMenuItem>
                  <Link href="#ethical-hacking" className="w-full">
                    Ethical Hacking
                  </Link>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <Link
              href="#exam"
              className="text-sm font-medium hover:text-primary"
            >
              Exam Preparation
            </Link>
          </nav>
          <div className="md:hidden">
            <Button variant="ghost" size="icon">
              <span className="sr-only">Toggle menu</span>
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="24"
                height="24"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="h-6 w-6"
              >
                <line x1="4" x2="20" y1="12" y2="12" />
                <line x1="4" x2="20" y1="6" y2="6" />
                <line x1="4" x2="20" y1="18" y2="18" />
              </svg>
            </Button>
          </div>
        </div>
      </header>

      <main className="flex-1">
        {/* Hero Section */}
        <section className="py-12 md:py-20">
          <div className="container px-4 md:px-6">
            <div className="grid gap-6 lg:grid-cols-2 lg:gap-12 items-center">
              <div className="space-y-4">
                <h1 className="text-3xl font-bold tracking-tighter sm:text-4xl md:text-5xl">
                  Master Cybersecurity Skills with Expert-Led Courses
                </h1>
                <p className="text-muted-foreground md:text-xl">
                  Gain practical knowledge in digital forensics and ethical
                  hacking through our comprehensive courses designed for all
                  skill levels.
                </p>
                <div className="flex flex-col sm:flex-row gap-3">
                  <Button size="lg" className="w-full sm:w-auto">
                    Learn More
                  </Button>
                  <Button
                    variant="outline"
                    size="lg"
                    className="w-full sm:w-auto"
                  >
                    View Courses
                  </Button>
                </div>
              </div>
              <div className="mx-auto lg:ml-auto">
                <Image
                  src="/placeholder.svg?height=500&width=500"
                  alt="Cybersecurity Training"
                  width={500}
                  height={500}
                  className="rounded-lg object-cover"
                  priority
                />
              </div>
            </div>
          </div>
        </section>

        {/* Learning Section */}
        <section id="learning" className="py-12 md:py-20 bg-muted/50">
          <div className="container px-4 md:px-6">
            <div className="flex flex-col items-center justify-center space-y-4 text-center mb-10">
              <div className="space-y-2">
                <h2 className="text-3xl font-bold tracking-tighter sm:text-4xl md:text-5xl">
                  Learning Paths
                </h2>
                <p className="max-w-[700px] text-muted-foreground md:text-xl">
                  Choose your specialized learning path and start your journey
                  to becoming a cybersecurity expert.
                </p>
              </div>
            </div>
            <div className="grid md:grid-cols-2 gap-6">
              <Card className="overflow-hidden border-0 shadow-lg bg-gradient-to-br from-purple-50 to-indigo-50 dark:from-purple-950/20 dark:to-indigo-950/20">
                <CardHeader className="pb-0">
                  <div className="w-12 h-12 rounded-full bg-purple-100 dark:bg-purple-900/20 flex items-center justify-center mb-4">
                    <FileText className="h-6 w-6 text-purple-600 dark:text-purple-400" />
                  </div>
                  <CardTitle className="text-2xl">Digital Forensics</CardTitle>
                  <CardDescription className="text-base">
                    Learn to investigate digital crimes and recover evidence
                  </CardDescription>
                </CardHeader>
                <CardContent className="pt-6">
                  <ul className="space-y-2 text-sm">
                    <li className="flex items-center">
                      <span className="mr-2 h-1.5 w-1.5 rounded-full bg-purple-600 dark:bg-purple-400"></span>
                      Data Recovery Techniques
                    </li>
                    <li className="flex items-center">
                      <span className="mr-2 h-1.5 w-1.5 rounded-full bg-purple-600 dark:bg-purple-400"></span>
                      Mobile Device Forensics
                    </li>
                    <li className="flex items-center">
                      <span className="mr-2 h-1.5 w-1.5 rounded-full bg-purple-600 dark:bg-purple-400"></span>
                      Network Forensics
                    </li>
                  </ul>
                </CardContent>
                <CardFooter>
                  <Button className="w-full bg-purple-600 hover:bg-purple-700 text-white">
                    Explore Forensics
                  </Button>
                </CardFooter>
              </Card>

              <Card className="overflow-hidden border-0 shadow-lg bg-gradient-to-br from-emerald-50 to-teal-50 dark:from-emerald-950/20 dark:to-teal-950/20">
                <CardHeader className="pb-0">
                  <div className="w-12 h-12 rounded-full bg-emerald-100 dark:bg-emerald-900/20 flex items-center justify-center mb-4">
                    <Shield className="h-6 w-6 text-emerald-600 dark:text-emerald-400" />
                  </div>
                  <CardTitle className="text-2xl">Ethical Hacking</CardTitle>
                  <CardDescription className="text-base">
                    Master the art of finding and fixing security
                    vulnerabilities
                  </CardDescription>
                </CardHeader>
                <CardContent className="pt-6">
                  <ul className="space-y-2 text-sm">
                    <li className="flex items-center">
                      <span className="mr-2 h-1.5 w-1.5 rounded-full bg-emerald-600 dark:bg-emerald-400"></span>
                      Penetration Testing
                    </li>
                    <li className="flex items-center">
                      <span className="mr-2 h-1.5 w-1.5 rounded-full bg-emerald-600 dark:bg-emerald-400"></span>
                      Web Application Security
                    </li>
                    <li className="flex items-center">
                      <span className="mr-2 h-1.5 w-1.5 rounded-full bg-emerald-600 dark:bg-emerald-400"></span>
                      Social Engineering
                    </li>
                  </ul>
                </CardContent>
                <CardFooter>
                  <Button className="w-full bg-emerald-600 hover:bg-emerald-700 text-white">
                    Explore Ethical Hacking
                  </Button>
                </CardFooter>
              </Card>
            </div>
          </div>
        </section>

        {/* Exam Preparation Section */}
        <section id="exam" className="py-12 md:py-20">
          <div className="container px-4 md:px-6">
            <div className="flex flex-col items-center justify-center space-y-4 text-center mb-10">
              <div className="space-y-2">
                <h2 className="text-3xl font-bold tracking-tighter sm:text-4xl md:text-5xl">
                  Exam Preparation
                </h2>
                <p className="max-w-[700px] text-muted-foreground md:text-xl">
                  Get ready for industry-recognized certifications with our
                  comprehensive exam preparation materials.
                </p>
              </div>
            </div>
            <div className="grid md:grid-cols-2 gap-8">
              <div className="relative group">
                <div className="absolute -inset-0.5 bg-gradient-to-r from-pink-600 to-purple-600 rounded-xl blur opacity-75 group-hover:opacity-100 transition duration-1000 group-hover:duration-200"></div>
                <div className="relative bg-background rounded-lg p-6 h-full flex flex-col">
                  <div className="mb-4 flex items-center">
                    <Bookmark className="h-8 w-8 text-pink-500 mr-3" />
                    <h3 className="text-xl font-bold">
                      Forensic Certification
                    </h3>
                  </div>
                  <p className="text-muted-foreground mb-4">
                    Prepare for GCFA, CCFE, and other digital forensics
                    certifications with our specialized materials.
                  </p>
                  <div className="mt-auto space-y-4">
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Practice Tests</span>
                      <span className="text-sm font-medium">500+</span>
                    </div>
                    <div className="w-full bg-muted rounded-full h-2">
                      <div className="bg-gradient-to-r from-pink-500 to-purple-500 h-2 rounded-full w-[85%]"></div>
                    </div>
                    <Button
                      variant="outline"
                      className="w-full mt-4 border-pink-500 text-pink-500 hover:bg-pink-500 hover:text-white"
                    >
                      Start Preparation
                    </Button>
                  </div>
                </div>
              </div>

              <div className="relative group">
                <div className="absolute -inset-0.5 bg-gradient-to-r from-amber-500 to-orange-600 rounded-xl blur opacity-75 group-hover:opacity-100 transition duration-1000 group-hover:duration-200"></div>
                <div className="relative bg-background rounded-lg p-6 h-full flex flex-col">
                  <div className="mb-4 flex items-center">
                    <Shield className="h-8 w-8 text-amber-500 mr-3" />
                    <h3 className="text-xl font-bold">
                      Ethical Hacking Certification
                    </h3>
                  </div>
                  <p className="text-muted-foreground mb-4">
                    Get ready for CEH, OSCP, and other ethical hacking
                    certifications with comprehensive study materials.
                  </p>
                  <div className="mt-auto space-y-4">
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Lab Exercises</span>
                      <span className="text-sm font-medium">300+</span>
                    </div>
                    <div className="w-full bg-muted rounded-full h-2">
                      <div className="bg-gradient-to-r from-amber-500 to-orange-500 h-2 rounded-full w-[75%]"></div>
                    </div>
                    <Button
                      variant="outline"
                      className="w-full mt-4 border-amber-500 text-amber-500 hover:bg-amber-500 hover:text-white"
                    >
                      Start Preparation
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Social Media Section */}
        <section id="social" className="py-12 md:py-20 bg-muted/50">
          <div className="container px-4 md:px-6">
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
                href="#"
                className="group flex flex-col items-center p-6 bg-background rounded-xl shadow-sm transition-all hover:shadow-md"
              >
                <div className="h-16 w-16 rounded-full bg-blue-100 flex items-center justify-center mb-4 group-hover:bg-blue-600 transition-colors">
                  <Facebook className="h-8 w-8 text-blue-600 group-hover:text-white transition-colors" />
                </div>
                <h3 className="font-medium">Facebook</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  @cyberlearn
                </p>
              </a>

              <a
                href="#"
                className="group flex flex-col items-center p-6 bg-background rounded-xl shadow-sm transition-all hover:shadow-md"
              >
                <div className="h-16 w-16 rounded-full bg-red-100 flex items-center justify-center mb-4 group-hover:bg-red-600 transition-colors">
                  <Youtube className="h-8 w-8 text-red-600 group-hover:text-white transition-colors" />
                </div>
                <h3 className="font-medium">YouTube</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  CyberLearn Channel
                </p>
              </a>

              <a
                href="#"
                className="group flex flex-col items-center p-6 bg-background rounded-xl shadow-sm transition-all hover:shadow-md"
              >
                <div className="h-16 w-16 rounded-full bg-black/10 flex items-center justify-center mb-4 group-hover:bg-black transition-colors">
                  <Twitter className="h-8 w-8 text-black group-hover:text-white transition-colors" />
                </div>
                <h3 className="font-medium">X.com</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  @cyberlearn_edu
                </p>
              </a>

              <a
                href="#"
                className="group flex flex-col items-center p-6 bg-background rounded-xl shadow-sm transition-all hover:shadow-md"
              >
                <div className="h-16 w-16 rounded-full bg-pink-100 flex items-center justify-center mb-4 group-hover:bg-pink-600 transition-colors">
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    width="24"
                    height="24"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    className="h-8 w-8 text-pink-600 group-hover:text-white transition-colors"
                  >
                    <path d="M9 12a9 9 0 0 0 9 9" />
                    <path d="M9 3v18" />
                    <path d="M15 12a9 9 0 0 1-9 9" />
                    <path d="M15 3v18" />
                  </svg>
                </div>
                <h3 className="font-medium">TikTok</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  @cyberlearn_tips
                </p>
              </a>
            </div>
          </div>
        </section>

        {/* About Us Section */}
        <section id="about" className="py-12 md:py-20">
          <div className="container px-4 md:px-6">
            <div className="grid gap-6 lg:grid-cols-2 lg:gap-12 items-center">
              <div className="mx-auto lg:order-last">
                <Image
                  src="/placeholder.svg?height=400&width=400"
                  alt="About CyberLearn"
                  width={400}
                  height={400}
                  className="rounded-lg object-cover"
                />
              </div>
              <div className="space-y-4">
                <h2 className="text-3xl font-bold tracking-tighter sm:text-4xl">
                  About CyberLearn
                </h2>
                <p className="text-muted-foreground">
                  CyberLearn is a premier e-learning platform dedicated to
                  cybersecurity education. Founded by industry experts with over
                  20 years of combined experience, we're committed to making
                  high-quality cybersecurity training accessible to everyone.
                </p>
                <p className="text-muted-foreground">
                  Our courses are designed with a hands-on approach, ensuring
                  that students not only understand theoretical concepts but can
                  also apply them in real-world scenarios. With CyberLearn,
                  you're not just learning—you're preparing for a successful
                  career in cybersecurity.
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
      </main>

      {/* Footer */}
      <footer className="border-t py-6 md:py-8">
        <div className="container flex flex-col gap-4 md:flex-row md:gap-8 px-4 md:px-6">
          <div className="flex flex-col gap-2 md:gap-4 md:w-1/3">
            <div className="flex items-center gap-2 font-bold text-xl">
              <Shield className="h-6 w-6 text-primary" />
              <span>CyberLearn</span>
            </div>
            <p className="text-sm text-muted-foreground">
              Empowering the next generation of cybersecurity professionals
              through quality education and practical training.
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
        <div className="container flex flex-col md:flex-row justify-between items-center gap-4 border-t mt-8 pt-8 px-4 md:px-6">
          <p className="text-xs text-muted-foreground">
            © {new Date().getFullYear()} CyberLearn. All rights reserved.
          </p>
          <div className="flex items-center gap-4">
            <Link
              href="#"
              className="text-muted-foreground hover:text-foreground"
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
      </footer>
    </div>
  );
}
