"use client";
import Link from "next/link";
import { Shield, ChevronDown, Menu, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import Image from "next/image";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Sheet,
  SheetContent,
  SheetTrigger,
  SheetClose,
} from "@/components/ui/sheet";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { useState } from "react";
export default function Navigation() {
  const [openItems, setOpenItems] = useState<Record<string, boolean>>({
    learning: false,
    social: false,
    exam: false,
  });

  const toggleItem = (item: string) => {
    setOpenItems((prev) => ({
      ...prev,
      [item]: !prev[item],
    }));
  };
  return (
    <>
      <header className="border-b sticky top-0 z-50 bg-background w-full">
        <div className="container mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 pt-2 pb-2">
          <div className="flex h-16 items-center justify-between">
            <div className="gap-2 font-bold text-xl">
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
            <nav className="hidden md:flex items-center gap-6">
              <Link href="/" className="text-sm font-medium hover:text-primary">
                Home
              </Link>
              <Link
                href="/about-us"
                className="text-sm font-medium hover:text-primary"
              >
                About Us
              </Link>
              <DropdownMenu>
                <DropdownMenuTrigger className="flex items-center gap-1 text-sm font-medium hover:text-primary">
                  Learning <ChevronDown className="h-4 w-4" />
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  <DropdownMenuItem>
                    <Link href="/learning/exam/CHFI" className="w-full">
                      Forensic
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuItem>
                    <Link href="/learning/exam/CEH" className="w-full">
                      Ethical Hacking
                    </Link>
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
              <DropdownMenu>
                <DropdownMenuTrigger className="flex items-center gap-1 text-sm font-medium hover:text-primary">
                  Social Media <ChevronDown className="h-4 w-4" />
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  <DropdownMenuItem>
                    <Link href="#facebook" className="w-full">
                      Facebook
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuItem>
                    <Link href="#youtube" className="w-full">
                      YouTube
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuItem>
                    <Link href="#twitter" className="w-full">
                      X.com
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuItem>
                    <Link href="#tiktok" className="w-full">
                      TikTok
                    </Link>
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
              <DropdownMenu>
                <DropdownMenuTrigger className="flex items-center gap-1 text-sm font-medium hover:text-primary">
                  Exam Preparation <ChevronDown className="h-4 w-4" />
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  <DropdownMenuItem>
                    <Link href="/preparations/exam/CHFI" className="w-full">
                      Forensic
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuItem>
                    <Link href="/preparations/exam/CEH" className="w-full">
                      Ethical Hacking
                    </Link>
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </nav>

            {/* Mobile Navigation */}
            <div className="md:hidden">
              <Sheet>
                <SheetTrigger asChild>
                  <Button variant="ghost" size="icon">
                    <Menu className="h-6 w-6" />
                    <span className="sr-only">Toggle menu</span>
                  </Button>
                </SheetTrigger>
                <SheetContent side="left" className="w-[300px] sm:w-[350px]">
                  <div className="flex flex-col h-full">
                    <div className="flex items-center justify-between py-4 border-b">
                      <div className="flex items-center gap-2 font-bold text-xl">
                        <Shield className="h-6 w-6 text-primary" />
                        <span>CyberLearn</span>
                      </div>
                      <SheetClose asChild>
                        <Button variant="ghost" size="icon">
                          <X className="h-5 w-5" />
                          <span className="sr-only">Close menu</span>
                        </Button>
                      </SheetClose>
                    </div>

                    <div className="flex flex-col space-y-3 py-4">
                      <SheetClose asChild>
                        <Link
                          href="/"
                          className="px-4 py-2 text-base font-medium hover:bg-muted rounded-md"
                        >
                          Home
                        </Link>
                      </SheetClose>

                      <SheetClose asChild>
                        <Link
                          href="#about"
                          className="px-4 py-2 text-base font-medium hover:bg-muted rounded-md"
                        >
                          About Us
                        </Link>
                      </SheetClose>

                      <Collapsible
                        open={openItems.learning}
                        onOpenChange={() => toggleItem("learning")}
                        className="w-full"
                      >
                        <CollapsibleTrigger asChild>
                          <Button
                            variant="ghost"
                            className="w-full justify-between px-4 py-2 text-base font-medium hover:bg-muted rounded-md"
                          >
                            <span>Learning</span>
                            <ChevronDown
                              className={`h-4 w-4 transition-transform ${
                                openItems.learning ? "rotate-180" : ""
                              }`}
                            />
                          </Button>
                        </CollapsibleTrigger>
                        <CollapsibleContent className="pl-4 space-y-1">
                          <SheetClose asChild>
                            <Link
                              href="#forensic"
                              className="block px-4 py-2 text-sm hover:bg-muted rounded-md"
                            >
                              Forensic
                            </Link>
                          </SheetClose>
                          <SheetClose asChild>
                            <Link
                              href="#ethical-hacking"
                              className="block px-4 py-2 text-sm hover:bg-muted rounded-md"
                            >
                              Ethical Hacking
                            </Link>
                          </SheetClose>
                        </CollapsibleContent>
                      </Collapsible>

                      <Collapsible
                        open={openItems.social}
                        onOpenChange={() => toggleItem("social")}
                        className="w-full"
                      >
                        <CollapsibleTrigger asChild>
                          <Button
                            variant="ghost"
                            className="w-full justify-between px-4 py-2 text-base font-medium hover:bg-muted rounded-md"
                          >
                            <span>Social Media</span>
                            <ChevronDown
                              className={`h-4 w-4 transition-transform ${
                                openItems.social ? "rotate-180" : ""
                              }`}
                            />
                          </Button>
                        </CollapsibleTrigger>
                        <CollapsibleContent className="pl-4 space-y-1">
                          <SheetClose asChild>
                            <Link
                              href="#facebook"
                              className="block px-4 py-2 text-sm hover:bg-muted rounded-md"
                            >
                              Facebook
                            </Link>
                          </SheetClose>
                          <SheetClose asChild>
                            <Link
                              href="#youtube"
                              className="block px-4 py-2 text-sm hover:bg-muted rounded-md"
                            >
                              YouTube
                            </Link>
                          </SheetClose>
                          <SheetClose asChild>
                            <Link
                              href="#twitter"
                              className="block px-4 py-2 text-sm hover:bg-muted rounded-md"
                            >
                              X.com
                            </Link>
                          </SheetClose>
                          <SheetClose asChild>
                            <Link
                              href="#tiktok"
                              className="block px-4 py-2 text-sm hover:bg-muted rounded-md"
                            >
                              TikTok
                            </Link>
                          </SheetClose>
                        </CollapsibleContent>
                      </Collapsible>

                      <Collapsible
                        open={openItems.exam}
                        onOpenChange={() => toggleItem("exam")}
                        className="w-full"
                      >
                        <CollapsibleTrigger asChild>
                          <Button
                            variant="ghost"
                            className="w-full justify-between px-4 py-2 text-base font-medium hover:bg-muted rounded-md"
                          >
                            <span>Exam Preparation</span>
                            <ChevronDown
                              className={`h-4 w-4 transition-transform ${
                                openItems.exam ? "rotate-180" : ""
                              }`}
                            />
                          </Button>
                        </CollapsibleTrigger>
                        <CollapsibleContent className="pl-4 space-y-1">
                          <SheetClose asChild>
                            <Link
                              href="#forensic-exam"
                              className="block px-4 py-2 text-sm hover:bg-muted rounded-md"
                            >
                              Forensic
                            </Link>
                          </SheetClose>
                          <SheetClose asChild>
                            <Link
                              href="#ethical-hacking-exam"
                              className="block px-4 py-2 text-sm hover:bg-muted rounded-md"
                            >
                              Ethical Hacking
                            </Link>
                          </SheetClose>
                        </CollapsibleContent>
                      </Collapsible>
                    </div>

                    <div className="mt-auto border-t pt-4">
                      <Button className="w-full">Get Started</Button>
                    </div>
                  </div>
                </SheetContent>
              </Sheet>
            </div>
          </div>
        </div>
      </header>
    </>
  );
}
