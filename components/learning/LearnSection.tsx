import { FileText, Shield } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "../ui/card";
import { Button } from "../ui/button";
import Link from "next/link";

export default function LearningSection() {
  return (
    <>
      <section id="learning" className="py-12 md:py-20 bg-muted/50 w-full">
        <div className="container mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col items-center justify-center space-y-4 text-center mb-10">
            <div className="space-y-2">
              <h2 className="text-3xl font-bold tracking-tighter sm:text-4xl md:text-5xl">
                Learning Paths
              </h2>
              <p className="max-w-[700px] text-muted-foreground md:text-xl">
                Choose your specialized learning path and start your journey to
                becoming a cybersecurity expert.
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
                <Link
                  href="/learning/exam/CHFI"
                  className="inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 h-10 px-4 py-2 w-full bg-purple-600 hover:bg-purple-700 text-white"
                >
                  Explore Forensics
                </Link>
              </CardFooter>
            </Card>

            <Card className="overflow-hidden border-0 shadow-lg bg-gradient-to-br from-emerald-50 to-teal-50 dark:from-emerald-950/20 dark:to-teal-950/20">
              <CardHeader className="pb-0">
                <div className="w-12 h-12 rounded-full bg-emerald-100 dark:bg-emerald-900/20 flex items-center justify-center mb-4">
                  <Shield className="h-6 w-6 text-emerald-600 dark:text-emerald-400" />
                </div>
                <CardTitle className="text-2xl">Ethical Hacking</CardTitle>
                <CardDescription className="text-base">
                  Master the art of finding and fixing security vulnerabilities
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
                <Link
                  href="/learning/exam/CEH"
                  className="inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 h-10 px-4 py-2 w-full bg-emerald-600 hover:bg-emerald-700 text-white"
                >
                  Explore Ethical Hacking
                </Link>
              </CardFooter>
            </Card>
          </div>
        </div>
      </section>
    </>
  );
}
