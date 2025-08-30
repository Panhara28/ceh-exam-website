"use client";

import { Card, CardContent } from "@/components/ui/card";

type LearningInterfaceProps = {
  learningData: any[];
};

export default function LearningInterface({
  learningData,
}: LearningInterfaceProps) {
  return (
    <div className="container mx-auto py-8 px-4 max-w-4xl">
      <h1 className="text-2xl font-bold mb-6 text-center">
        Computer Hacking Forensic Investigator (CHFI) Exam Practice
      </h1>

      <div className="text-sm mb-6">
        Showing 1-{learningData.length} of {learningData.length} questions
      </div>

      <div className="space-y-6">
        {learningData.map((question) => (
          <Card key={question.id} className="shadow-sm">
            <CardContent className="pt-6">
              <div className="mb-4">
                <span className="font-semibold text-sm bg-gray-100 px-2 py-1 rounded-md mr-2">
                  Question {question.id}
                </span>
                <p className="mt-2">{question.question}</p>
              </div>

              <div className="space-y-2 mt-4">
                {question.options.map((option: any, index: number) => (
                  <div
                    key={index}
                    className={`p-3 rounded-md border ${
                      index === question.correctAnswer
                        ? "bg-green-50 border-green-200"
                        : "bg-white border-gray-200"
                    }`}
                  >
                    <div className="flex items-start">
                      <div className="mr-2 font-medium">
                        {String.fromCharCode(65 + index)}.
                      </div>
                      <div>{option}</div>
                      {index === question.correctAnswer && (
                        <div className="ml-auto text-green-600 text-sm font-medium">
                          Correct Answer
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
