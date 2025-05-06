import { Bookmark, Shield } from "lucide-react";
import { Button } from "../ui/button";
import Link from "next/link";
import { CEH_DUMP_QUESTIONS } from "@/data/questions";
import { CHFI_DUMP_QUESTIONS } from "@/data/chfi";

export default function ExamPreparationSection() {
  return (
    <>
      <section id="exam" className="py-12 md:py-20 w-full">
        <div className="container mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
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
                  <h3 className="text-xl font-bold">Forensic Certification</h3>
                </div>
                <p className="text-muted-foreground mb-4">
                  Prepare for GCFA, CCFE, and other digital forensics
                  certifications with our specialized materials.
                </p>
                <div className="mt-auto space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-sm">Practice Tests</span>
                    <span className="text-sm font-medium">
                      {CHFI_DUMP_QUESTIONS.length}+
                    </span>
                  </div>
                  <div className="w-full bg-muted rounded-full h-2">
                    <div className="bg-gradient-to-r from-pink-500 to-purple-500 h-2 rounded-full w-[85%]"></div>
                  </div>
                  <Link
                    href="/preparations/exam/CEH"
                    className="inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 border bg-background h-10 px-4 py-2 w-full mt-4 border-pink-500 text-pink-500 hover:bg-pink-500 hover:text-white"
                  >
                    Start Preparation
                  </Link>
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
                    <span className="text-sm">Questions</span>
                    <span className="text-sm font-medium">
                      {CEH_DUMP_QUESTIONS.length}+
                    </span>
                  </div>
                  <div className="w-full bg-muted rounded-full h-2">
                    <div className="bg-gradient-to-r from-amber-500 to-orange-500 h-2 rounded-full w-[75%]"></div>
                  </div>
                  <Link
                    href="/preparations/exam/CEH"
                    className="inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 border bg-background h-10 px-4 py-2 w-full mt-4 border-amber-500 text-amber-500 hover:bg-amber-500 hover:text-white"
                  >
                    Start Preparation
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
