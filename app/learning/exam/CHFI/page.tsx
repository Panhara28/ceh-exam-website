import { CHFI_DUMP_QUESTIONS } from "@/data/chfi";
import LearningInterface from "@/components/learning-interface";
import { Metadata } from "next";

export default function LearningChfiPage() {
  return <LearningInterface learningData={CHFI_DUMP_QUESTIONS} />;
}

export const metadata: Metadata = {
  title: "CHFI Learning | Learn. Secure. Protect.",
  description:
    "your trusted cybersecurity learning platform in Cambodia. We empower individuals and organizations with practical knowledge, training, and tools to defend against digital threats. Explore hands-on tutorials, up-to-date cybersecurity news, and expert guidance to stay secure in an ever-evolving digital world.",
};
